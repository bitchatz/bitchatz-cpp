#import "platforms/apple/bluetooth.h"
#include "bitchat/core/constants.h"

// ============================================================================
// Objective-C Implementation - Pure BLE Implementation
// ============================================================================

// Platform-specific constants (using C++ constants)
static NSString *const SERVICE_UUID = @(bitchat::constants::BLE_SERVICE_UUID.c_str());
static NSString *const CHARACTERISTIC_UUID = @(bitchat::constants::BLE_CHARACTERISTIC_UUID.c_str());

@implementation AppleBluetooth
{
    // Instance variables for callback properties
    void (^_peerDisconnectedCallback)(NSString *); // Callback when a peer disconnects
    void (^_packetReceivedCallback)(NSData *);     // Callback when a packet is received
}

// ============================================================================
// Callback Properties - Manual getters and setters
// ============================================================================

/**
 * @brief Getter for peer disconnection callback
 * @return The stored callback block
 */
- (void (^)(NSString *))peerDisconnectedCallback
{
    return _peerDisconnectedCallback;
}

/**
 * @brief Setter for peer disconnection callback
 * @param callback The callback block to store
 */
- (void)setPeerDisconnectedCallback:(void (^)(NSString *))callback
{
    _peerDisconnectedCallback = [callback copy]; // Copy to ensure block survives
}

/**
 * @brief Getter for packet received callback
 * @return The stored callback block
 */
- (void (^)(NSData *))packetReceivedCallback
{
    return _packetReceivedCallback;
}

/**
 * @brief Setter for packet received callback
 * @param callback The callback block to store
 */
- (void)setPacketReceivedCallback:(void (^)(NSData *))callback
{
    _packetReceivedCallback = [callback copy]; // Copy to ensure block survives
}

// ============================================================================
// Initialization and Lifecycle
// ============================================================================

/**
 * @brief Initialize the AppleBluetooth instance
 *
 * Sets up the Core Bluetooth managers (Central and Peripheral) and initializes
 * all necessary data structures for managing BLE connections.
 */
- (instancetype)init
{
    self = [super init];
    if (self)
    {
        self.ready = NO;                                                                 // Not ready until managers are powered on
        self.lock = [[NSLock alloc] init];                                               // Thread safety lock
        self.bleQueue = dispatch_queue_create("com.bitchat.ble", DISPATCH_QUEUE_SERIAL); // Serial queue for BLE operations

        // Initialize managers on main queue (required for Core Bluetooth)
        dispatch_async(dispatch_get_main_queue(), ^{
            // Central manager handles scanning and connecting to other devices
            self.centralManager = [[CBCentralManager alloc] initWithDelegate:self queue:self.bleQueue];
            // Peripheral manager handles advertising and accepting connections
            self.peripheralManager = [[CBPeripheralManager alloc] initWithDelegate:self queue:self.bleQueue];
        });

        // Initialize collections for managing BLE connections
        self.discoveredPeripherals = [[NSMutableArray alloc] init];          // Devices found during scanning
        self.connectedPeripherals = [[NSMutableDictionary alloc] init];      // Currently connected devices
        self.peripheralCharacteristics = [[NSMutableDictionary alloc] init]; // Characteristics for each peripheral
        self.subscribedCentrals = [[NSMutableArray alloc] init];             // Centrals subscribed to our service
    }
    return self;
}

/**
 * @brief Initialize the Bluetooth system
 *
 * Waits for both Central and Peripheral managers to be powered on before
 * marking the system as ready for operations.
 *
 * @return YES if initialization successful, NO otherwise
 */
- (BOOL)initialize
{
    // Wait for both managers to be ready (this can take a few seconds)
    while (self.centralManager.state != CBManagerStatePoweredOn ||
           self.peripheralManager.state != CBManagerStatePoweredOn)
    {
        // Run the run loop to allow state updates to process
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:bitchat::constants::BLE_SCAN_INTERVAL_SECONDS]];
    }

    self.ready = YES; // Mark system as ready for operations
    return YES;
}

/**
 * @brief Start Bluetooth operations
 *
 * Once called, the system will automatically start scanning for other devices
 * and advertising its own presence based on delegate callbacks.
 *
 * @return YES if started successfully, NO if not ready
 */
- (BOOL)start
{
    if (!self.ready)
    {
        return NO;
    }

    // Start scanning and advertising will be handled by delegate methods
    // when the managers reach powered on state
    return YES;
}

/**
 * @brief Stop all Bluetooth operations
 *
 * Stops scanning for devices and stops advertising this device's presence.
 */
- (void)stop
{
    if (self.centralManager)
    {
        [self.centralManager stopScan]; // Stop scanning for other devices
    }

    if (self.peripheralManager)
    {
        [self.peripheralManager stopAdvertising]; // Stop advertising this device
    }
}

// ============================================================================
// Packet Sending Methods
// ============================================================================

/**
 * @brief Send a packet to all connected peers
 *
 * Broadcasts the packet to all connected peripherals and subscribed centrals.
 *
 * @param packetData The packet data to send
 * @return YES if sent successfully, NO if not ready
 */
- (BOOL)sendPacket:(NSData *)packetData
{
    if (!self.ready)
        return NO;

    // Send to all connected peripherals (devices we're connected to)
    for (CBPeripheral *peripheral in self.connectedPeripherals.allValues)
    {
        CBCharacteristic *characteristic = [self.peripheralCharacteristics objectForKey:peripheral];

        if (characteristic && peripheral.state == CBPeripheralStateConnected)
        {
            // Write packet to the characteristic without waiting for response
            [peripheral writeValue:packetData
                 forCharacteristic:characteristic
                              type:CBCharacteristicWriteWithoutResponse];
        }
    }

    // Send to subscribed centrals (devices connected to us)
    if (self.mutableCharacteristic && self.subscribedCentrals.count > 0)
    {
        // Update the characteristic value for all subscribed centrals
        [self.peripheralManager updateValue:packetData
                          forCharacteristic:self.mutableCharacteristic
                       onSubscribedCentrals:self.subscribedCentrals];
    }

    return YES;
}

/**
 * @brief Send a packet to a specific peripheral
 *
 * @param packetData The packet data to send
 * @param peripheral The target peripheral device
 * @return YES if sent successfully, NO if not ready or peripheral not connected
 */
- (BOOL)sendPacket:(NSData *)packetData toPeripheral:(CBPeripheral *)peripheral
{
    if (!self.ready || !peripheral)
    {
        return NO;
    }

    CBCharacteristic *characteristic = [self.peripheralCharacteristics objectForKey:peripheral];

    if (characteristic && peripheral.state == CBPeripheralStateConnected)
    {
        // Write packet to the specific peripheral's characteristic
        [peripheral writeValue:packetData
             forCharacteristic:characteristic
                          type:CBCharacteristicWriteWithoutResponse];

        return YES;
    }

    return NO;
}

/**
 * @brief Send a packet to a specific peer by ID
 *
 * @param packetData The packet data to send
 * @param peerId The target peer's identifier
 * @return YES if sent successfully, NO if peer not found
 */
- (BOOL)sendPacket:(NSData *)packetData toPeer:(NSString *)peerId
{
    // Find peripheral for this peer ID
    for (NSString *peerIdKey in self.connectedPeripherals.allKeys)
    {
        if ([peerIdKey isEqualToString:peerId])
        {
            CBPeripheral *peripheral = [self.connectedPeripherals objectForKey:peerIdKey];
            return [self sendPacket:packetData toPeripheral:peripheral];
        }
    }

    return NO; // Peer not found
}

// ============================================================================
// State and Information Methods
// ============================================================================

/**
 * @brief Check if the Bluetooth system is ready for operations
 * @return YES if ready, NO otherwise
 */
- (BOOL)isReady
{
    return self.ready;
}

/**
 * @brief Get the local device's peer identifier
 *
 * Generates a random 8-character hex ID if not already set.
 * This ID is used to identify this device to other peers.
 *
 * @return The local peer ID as a string
 */
- (NSString *)getLocalPeerId
{
    // Generate a random peer ID if not set
    if (!self.localPeerId)
    {
        // Generate 8 random bytes (64 bits) for strong collision resistance like Swift
        NSMutableString *peerId = [NSMutableString string];

        for (size_t i = 0; i < 8; i++)
        {
            [peerId appendFormat:@"%02x", arc4random_uniform(256)]; // Generate random hex byte
        }

        self.localPeerId = [peerId copy];
    }

    return self.localPeerId;
}

/**
 * @brief Get the number of currently connected peers
 * @return Number of connected peripherals
 */
- (NSUInteger)getConnectedPeersCount
{
    return self.connectedPeripherals.count;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * @brief Get the BLE service UUID
 * @return The service UUID string
 */
+ (NSString *)serviceUUID
{
    return SERVICE_UUID;
}

/**
 * @brief Get the BLE characteristic UUID
 * @return The characteristic UUID string
 */
+ (NSString *)characteristicUUID
{
    return CHARACTERISTIC_UUID;
}

// ============================================================================
// CBCentralManagerDelegate - Central Role (Scanner/Client)
// ============================================================================

/**
 * @brief Called when the central manager's state changes
 *
 * When the central manager is powered on, it automatically starts scanning
 * for other devices advertising our service.
 *
 * @param central The central manager instance
 */
- (void)centralManagerDidUpdateState:(CBCentralManager *)central
{
    if (central.state == CBManagerStatePoweredOn)
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self startScanning]; // Start scanning for other devices
        });
    }
}

/**
 * @brief Called when a peripheral is discovered during scanning
 *
 * Automatically attempts to connect to discovered peripherals that
 * are advertising our service.
 *
 * @param central The central manager
 * @param peripheral The discovered peripheral
 * @param advertisementData Advertisement data from the peripheral
 * @param RSSI Signal strength indicator
 */
- (void)centralManager:(CBCentralManager *)central
    didDiscoverPeripheral:(CBPeripheral *)peripheral
        advertisementData:(NSDictionary<NSString *, id> *)advertisementData
                     RSSI:(NSNumber *)RSSI
{
    if (![self.discoveredPeripherals containsObject:peripheral])
    {
        [self.discoveredPeripherals addObject:peripheral];              // Track discovered peripheral
        peripheral.delegate = self;                                     // Set ourselves as delegate for peripheral events
        [self.centralManager connectPeripheral:peripheral options:nil]; // Attempt connection
    }
}

/**
 * @brief Called when successfully connected to a peripheral
 *
 * Stores the peripheral and starts service discovery to find our
 * communication characteristic.
 *
 * @param central The central manager
 * @param peripheral The connected peripheral
 */
- (void)centralManager:(CBCentralManager *)central
    didConnectPeripheral:(CBPeripheral *)peripheral
{
    // Use UUID as temporary peer ID until we get the real one from announce packet
    NSString *tempID = peripheral.identifier.UUIDString;
    [self.connectedPeripherals setObject:peripheral forKey:tempID];          // Store connected peripheral
    [peripheral discoverServices:@[ [CBUUID UUIDWithString:SERVICE_UUID] ]]; // Discover our service
}

/**
 * @brief Called when a peripheral disconnects
 *
 * Removes the peripheral from tracking and notifies the C++ bridge
 * about the disconnection.
 *
 * @param central The central manager
 * @param peripheral The disconnected peripheral
 * @param error Disconnection error (if any)
 */
- (void)centralManager:(CBCentralManager *)central
    didDisconnectPeripheral:(CBPeripheral *)peripheral
                      error:(NSError *)error
{
    NSString *tempID = peripheral.identifier.UUIDString;
    [self.connectedPeripherals removeObjectForKey:tempID];          // Remove from connected devices
    [self.peripheralCharacteristics removeObjectForKey:peripheral]; // Remove characteristic reference

    // Notify C++ bridge about disconnection
    if (self.peerDisconnectedCallback)
    {
        self.peerDisconnectedCallback(tempID);
    }
}

/**
 * @brief Called when connection to a peripheral fails
 *
 * Removes the peripheral from discovered devices list.
 *
 * @param central The central manager
 * @param peripheral The peripheral that failed to connect
 * @param error Connection error
 */
- (void)centralManager:(CBCentralManager *)central
    didFailToConnectPeripheral:(CBPeripheral *)peripheral
                         error:(NSError *)error
{
    [self.discoveredPeripherals removeObject:peripheral]; // Remove from discovered devices
}

// ============================================================================
// CBPeripheralManagerDelegate - Peripheral Role (Advertiser/Server)
// ============================================================================

/**
 * @brief Called when the peripheral manager's state changes
 *
 * When the peripheral manager is powered on, it sets up the service
 * and starts advertising this device's presence.
 *
 * @param peripheral The peripheral manager
 */
- (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral
{
    if (peripheral.state == CBManagerStatePoweredOn)
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self setupPeripheral];  // Set up our service and characteristic
            [self startAdvertising]; // Start advertising our presence
        });
    }
}

/**
 * @brief Called when a central writes to our characteristic
 *
 * Receives incoming packets from connected centrals and forwards
 * them to the C++ bridge for processing.
 *
 * @param peripheral The peripheral manager
 * @param requests Array of write requests from centrals
 */
- (void)peripheralManager:(CBPeripheralManager *)peripheral
    didReceiveWriteRequests:(NSArray<CBATTRequest *> *)requests
{
    for (CBATTRequest *request in requests)
    {
        if (request.value && request.value.length >= bitchat::constants::BLE_MIN_PACKET_SIZE_BYTES)
        {
            // Forward the raw packet data to C++ bridge for processing
            if (self.packetReceivedCallback)
            {
                self.packetReceivedCallback(request.value);
            }
        }
        [peripheral respondToRequest:request withResult:CBATTErrorSuccess]; // Acknowledge the write
    }
}

/**
 * @brief Called when a central subscribes to our characteristic
 *
 * Tracks subscribed centrals so we can send them updates.
 *
 * @param peripheral The peripheral manager
 * @param central The subscribing central
 * @param characteristic The characteristic being subscribed to
 */
- (void)peripheralManager:(CBPeripheralManager *)peripheral
                         central:(CBCentral *)central
    didSubscribeToCharacteristic:(CBCharacteristic *)characteristic
{
    if (![self.subscribedCentrals containsObject:central])
    {
        [self.subscribedCentrals addObject:central]; // Track subscribed central
    }
}

/**
 * @brief Called when a central unsubscribes from our characteristic
 *
 * Removes the central from our subscribed list.
 *
 * @param peripheral The peripheral manager
 * @param central The unsubscribing central
 * @param characteristic The characteristic being unsubscribed from
 */
- (void)peripheralManager:(CBPeripheralManager *)peripheral
                             central:(CBCentral *)central
    didUnsubscribeFromCharacteristic:(CBCharacteristic *)characteristic
{
    [self.subscribedCentrals removeObject:central]; // Remove from subscribed list
}

/**
 * @brief Called when advertising starts
 *
 * @param peripheral The peripheral manager
 * @param error Advertising error (if any)
 */
- (void)peripheralManagerDidStartAdvertising:(CBPeripheralManager *)peripheral
                                       error:(NSError *)error
{
    // Advertising started successfully
}

/**
 * @brief Called when a service is added
 *
 * @param peripheral The peripheral manager
 * @param service The added service
 * @param error Service addition error (if any)
 */
- (void)peripheralManager:(CBPeripheralManager *)peripheral
            didAddService:(CBService *)service
                    error:(NSError *)error
{
    // Service added successfully
}

// ============================================================================
// CBPeripheralDelegate - Peripheral Discovery and Communication
// ============================================================================

/**
 * @brief Called when services are discovered on a peripheral
 *
 * Looks for our specific service and starts characteristic discovery.
 *
 * @param peripheral The peripheral
 * @param error Service discovery error (if any)
 */
- (void)peripheral:(CBPeripheral *)peripheral
    didDiscoverServices:(NSError *)error
{
    for (CBService *service in peripheral.services)
    {
        if ([service.UUID isEqual:[CBUUID UUIDWithString:SERVICE_UUID]])
        {
            // Found our service, now discover the characteristic
            [peripheral discoverCharacteristics:@[ [CBUUID UUIDWithString:CHARACTERISTIC_UUID] ]
                                     forService:service];
        }
    }
}

/**
 * @brief Called when characteristics are discovered on a service
 *
 * Stores the characteristic reference and enables notifications
 * to receive updates from the peripheral.
 *
 * @param peripheral The peripheral
 * @param service The service containing the characteristics
 * @param error Characteristic discovery error (if any)
 */
- (void)peripheral:(CBPeripheral *)peripheral
    didDiscoverCharacteristicsForService:(CBService *)service
                                   error:(NSError *)error
{
    for (CBCharacteristic *characteristic in service.characteristics)
    {
        if ([characteristic.UUID isEqual:[CBUUID UUIDWithString:CHARACTERISTIC_UUID]])
        {
            [self.peripheralCharacteristics setObject:characteristic forKey:peripheral]; // Store characteristic
            [peripheral setNotifyValue:YES forCharacteristic:characteristic];            // Enable notifications
        }
    }
}

/**
 * @brief Called when a characteristic value is updated
 *
 * Receives incoming packets from peripherals and forwards them
 * to the C++ bridge for processing.
 *
 * @param peripheral The peripheral
 * @param characteristic The updated characteristic
 * @param error Update error (if any)
 */
- (void)peripheral:(CBPeripheral *)peripheral
    didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic
                              error:(NSError *)error
{
    NSData *data = characteristic.value;

    if (!data || data.length < bitchat::constants::BLE_MIN_PACKET_SIZE_BYTES)
    {
        return; // Ignore invalid or too small packets
    }

    // Forward the raw packet data to C++ bridge for processing
    if (self.packetReceivedCallback)
    {
        self.packetReceivedCallback(data);
    }
}

/**
 * @brief Called when notification state changes for a characteristic
 *
 * @param peripheral The peripheral
 * @param characteristic The characteristic
 * @param error State change error (if any)
 */
- (void)peripheral:(CBPeripheral *)peripheral
    didUpdateNotificationStateForCharacteristic:(CBCharacteristic *)characteristic
                                          error:(NSError *)error
{
    // Notification state updated
}

// ============================================================================
// Private Helper Methods
// ============================================================================

/**
 * @brief Start scanning for other devices
 *
 * Scans for peripherals advertising our service UUID.
 */
- (void)startScanning
{
    if (self.centralManager.state == CBManagerStatePoweredOn)
    {
        NSDictionary *options = @{CBCentralManagerScanOptionAllowDuplicatesKey : @YES}; // Allow duplicate advertisements
        [self.centralManager scanForPeripheralsWithServices:@[ [CBUUID UUIDWithString:SERVICE_UUID] ]
                                                    options:options];
    }
}

/**
 * @brief Set up the peripheral service and characteristic
 *
 * Creates the BLE service and characteristic that other devices
 * can connect to and communicate through.
 */
- (void)setupPeripheral
{
    // Create the characteristic with read, write, and notify properties
    self.mutableCharacteristic = [[CBMutableCharacteristic alloc]
        initWithType:[CBUUID UUIDWithString:CHARACTERISTIC_UUID]
          properties:CBCharacteristicPropertyRead | CBCharacteristicPropertyWrite |
                     CBCharacteristicPropertyWriteWithoutResponse | CBCharacteristicPropertyNotify
               value:nil
         permissions:CBAttributePermissionsReadable | CBAttributePermissionsWriteable];

    // Create the service and add the characteristic
    CBMutableService *service = [[CBMutableService alloc]
        initWithType:[CBUUID UUIDWithString:SERVICE_UUID]
             primary:YES];
    service.characteristics = @[ self.mutableCharacteristic ];

    [self.peripheralManager addService:service]; // Add service to peripheral manager
}

/**
 * @brief Start advertising this device's presence
 *
 * Advertises the service UUID and local peer ID so other devices
 * can discover and connect to this device.
 */
- (void)startAdvertising
{
    if (self.peripheralManager.state == CBManagerStatePoweredOn)
    {
        NSString *localName = [self getLocalPeerId]; // Use peer ID as local name

        // Set up advertisement data
        NSDictionary *advertisementData = @{
            CBAdvertisementDataServiceUUIDsKey : @[ [CBUUID UUIDWithString:SERVICE_UUID] ], // Advertise our service
            CBAdvertisementDataLocalNameKey : localName                                     // Advertise our peer ID
        };

        [self.peripheralManager startAdvertising:advertisementData]; // Start advertising
    }
}

@end
