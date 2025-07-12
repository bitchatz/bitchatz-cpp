#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet_serializer.h"
#import "platforms/apple/bluetooth.h"
#include <memory>
#include <string>
#include <vector>

namespace bitchat {

// Bridge class that implements the C++ interface and forwards to Objective-C
class AppleBluetoothBridge : public BluetoothInterface {
private:
    AppleBluetooth* impl;
    std::string localPeerId;
    PacketSerializer serializer;
    
    // Callbacks
    PeerDisconnectedCallback peerDisconnectedCallback;
    PacketReceivedCallback packetReceivedCallback;

public:
    AppleBluetoothBridge() : impl(nil) {
        impl = [[AppleBluetooth alloc] init];
        if (impl) {
            // Set up callback bridges
            [impl setPeerDisconnectedCallback:^(NSString *peerId) {
                if (peerDisconnectedCallback) {
                    std::string cppPeerId = [peerId UTF8String];
                    peerDisconnectedCallback(cppPeerId);
                }
            }];
            
            [impl setPacketReceivedCallback:^(NSData *packetData) {
                if (packetReceivedCallback) {
                    // Convert NSData to BitchatPacket
                    std::vector<uint8_t> data((uint8_t*)packetData.bytes,
                                             (uint8_t*)packetData.bytes + packetData.length);
                    BitchatPacket packet = serializer.deserializePacket(data);
                    packetReceivedCallback(packet);
                }
            }];
        }
    }
    
    ~AppleBluetoothBridge() {
        if (impl) {
            [impl release];
        }
    }
    
    bool initialize() override {
        if (!impl) return false;
        return [impl initialize];
    }
    
    bool start() override {
        if (!impl) return false;
        return [impl start];
    }
    
    void stop() override {
        if (impl) {
            [impl stop];
        }
    }
    
    bool sendPacket(const BitchatPacket& packet) override {
        if (!impl) return false;
        
        std::vector<uint8_t> data = serializer.serializePacket(packet);
        NSData* nsData = [NSData dataWithBytes:data.data() length:data.size()];
        return [impl sendPacket:nsData];
    }
    
    bool sendPacketToPeer(const BitchatPacket& packet, const std::string& peerId) override {
        if (!impl) return false;
        
        std::vector<uint8_t> data = serializer.serializePacket(packet);
        NSData* nsData = [NSData dataWithBytes:data.data() length:data.size()];
        NSString* nsPeerId = [NSString stringWithUTF8String:peerId.c_str()];
        return [impl sendPacket:nsData toPeer:nsPeerId];
    }
    
    bool isReady() const override {
        if (!impl) return false;
        return [impl isReady];
    }
    
    std::string getLocalPeerId() const override {
        if (!impl) return "";
        NSString* peerId = [impl getLocalPeerId];
        return peerId ? [peerId UTF8String] : "";
    }
    
    
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override {
        peerDisconnectedCallback = callback;
    }
    
    void setPacketReceivedCallback(PacketReceivedCallback callback) override {
        packetReceivedCallback = callback;
    }
    
    size_t getConnectedPeersCount() const override {
        if (!impl) return 0;
        return [impl getConnectedPeersCount];
    }
};

// Factory function
std::unique_ptr<BluetoothInterface> createAppleBluetoothBridge() {
    return std::make_unique<AppleBluetoothBridge>();
}

} // namespace bitchat

// ============================================================================
// Objective-C Implementation - PURE BLE ONLY
// ============================================================================

// Constants
static NSString* const SERVICE_UUID = @"F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C";
static NSString* const CHARACTERISTIC_UUID = @"A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D";

@implementation AppleBluetooth {
    // Instance variables for callback properties
    void (^_peerDisconnectedCallback)(NSString*);
    void (^_packetReceivedCallback)(NSData*);
}

// Callback properties - implement getters and setters manually
- (void (^)(NSString*))peerDisconnectedCallback {
    return _peerDisconnectedCallback;
}

- (void)setPeerDisconnectedCallback:(void (^)(NSString*))callback {
    _peerDisconnectedCallback = [callback copy];
}

- (void (^)(NSData*))packetReceivedCallback {
    return _packetReceivedCallback;
}

- (void)setPacketReceivedCallback:(void (^)(NSData*))callback {
    _packetReceivedCallback = [callback copy];
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self.ready = NO;
        self.lock = [[NSLock alloc] init];
        self.bleQueue = dispatch_queue_create("com.bitchat.ble", DISPATCH_QUEUE_SERIAL);
        
        // Initialize managers on main queue
        dispatch_async(dispatch_get_main_queue(), ^{
            self.centralManager = [[CBCentralManager alloc] initWithDelegate:self queue:self.bleQueue];
            self.peripheralManager = [[CBPeripheralManager alloc] initWithDelegate:self queue:self.bleQueue];
        });
        
        self.discoveredPeripherals = [[NSMutableArray alloc] init];
        self.connectedPeripherals = [[NSMutableDictionary alloc] init];
        self.peripheralCharacteristics = [[NSMutableDictionary alloc] init];
        self.subscribedCentrals = [[NSMutableArray alloc] init];
    }
    return self;
}

- (BOOL)initialize {
    // Wait for both managers to be ready
    while (self.centralManager.state != CBManagerStatePoweredOn ||
           self.peripheralManager.state != CBManagerStatePoweredOn) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode 
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    
    self.ready = YES;
    return YES;
}

- (BOOL)start {
    if (!self.ready) {
        return NO;
    }
    
    // Start scanning and advertising will be handled by delegate methods
    return YES;
}

- (void)stop {
    if (self.centralManager) {
        [self.centralManager stopScan];
    }
    if (self.peripheralManager) {
        [self.peripheralManager stopAdvertising];
    }
}

- (BOOL)sendPacket:(NSData *)packetData {
    if (!self.ready) return NO;
    
    // Send to all connected peripherals
    for (CBPeripheral *peripheral in self.connectedPeripherals.allValues) {
        CBCharacteristic *characteristic = [self.peripheralCharacteristics objectForKey:peripheral];
        if (characteristic && peripheral.state == CBPeripheralStateConnected) {
            [peripheral writeValue:packetData
                 forCharacteristic:characteristic
                              type:CBCharacteristicWriteWithoutResponse];
        }
    }
    
    // Send to subscribed centrals
    if (self.mutableCharacteristic && self.subscribedCentrals.count > 0) {
        [self.peripheralManager updateValue:packetData
                          forCharacteristic:self.mutableCharacteristic
                       onSubscribedCentrals:self.subscribedCentrals];
    }
    
    return YES;
}

- (BOOL)sendPacket:(NSData *)packetData toPeripheral:(CBPeripheral *)peripheral {
    if (!self.ready || !peripheral) return NO;
    
    CBCharacteristic *characteristic = [self.peripheralCharacteristics objectForKey:peripheral];
    if (characteristic && peripheral.state == CBPeripheralStateConnected) {
        [peripheral writeValue:packetData
             forCharacteristic:characteristic
                          type:CBCharacteristicWriteWithoutResponse];
        return YES;
    }
    return NO;
}

- (BOOL)sendPacket:(NSData *)packetData toPeer:(NSString *)peerId {
    // Find peripheral for this peer ID
    for (NSString *peerIDKey in self.connectedPeripherals.allKeys) {
        if ([peerIDKey isEqualToString:peerId]) {
            CBPeripheral *peripheral = [self.connectedPeripherals objectForKey:peerIDKey];
            return [self sendPacket:packetData toPeripheral:peripheral];
        }
    }
    return NO;
}

- (BOOL)isReady {
    return self.ready;
}

- (NSString *)getLocalPeerId {
    // Generate a random peer ID if not set
    if (!self.localPeerId) {
        // Simple random ID generation (8 hex characters)
        NSMutableString *peerId = [NSMutableString string];
        for (int i = 0; i < 8; i++) {
            [peerId appendFormat:@"%02x", arc4random_uniform(256)];
        }
        self.localPeerId = [peerId copy];
    }
    return self.localPeerId;
}

- (NSUInteger)getConnectedPeersCount {
    return self.connectedPeripherals.count;
}

// Constants
+ (NSString *)serviceUUID {
    return SERVICE_UUID;
}

+ (NSString *)characteristicUUID {
    return CHARACTERISTIC_UUID;
}

// ============================================================================
// CBCentralManagerDelegate - PURE BLE ONLY
// ============================================================================

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    if (central.state == CBManagerStatePoweredOn) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self startScanning];
        });
    }
}

- (void)centralManager:(CBCentralManager *)central
    didDiscoverPeripheral:(CBPeripheral *)peripheral
        advertisementData:(NSDictionary<NSString *, id> *)advertisementData
                     RSSI:(NSNumber *)RSSI {
    if (![self.discoveredPeripherals containsObject:peripheral]) {
        [self.discoveredPeripherals addObject:peripheral];
        peripheral.delegate = self;
        [self.centralManager connectPeripheral:peripheral options:nil];
    }
}

- (void)centralManager:(CBCentralManager *)central
    didConnectPeripheral:(CBPeripheral *)peripheral {
    NSString *tempID = peripheral.identifier.UUIDString;
    [self.connectedPeripherals setObject:peripheral forKey:tempID];
    [peripheral discoverServices:@[ [CBUUID UUIDWithString:SERVICE_UUID] ]];
}

- (void)centralManager:(CBCentralManager *)central
    didDisconnectPeripheral:(CBPeripheral *)peripheral
                      error:(NSError *)error {
    NSString *tempID = peripheral.identifier.UUIDString;
    [self.connectedPeripherals removeObjectForKey:tempID];
    [self.peripheralCharacteristics removeObjectForKey:peripheral];
    
    if (self.peerDisconnectedCallback) {
        self.peerDisconnectedCallback(tempID);
    }
}

- (void)centralManager:(CBCentralManager *)central
    didFailToConnectPeripheral:(CBPeripheral *)peripheral
                                   error:(NSError *)error {
    [self.discoveredPeripherals removeObject:peripheral];
}

// ============================================================================
// CBPeripheralManagerDelegate - PURE BLE ONLY
// ============================================================================

- (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral {
    if (peripheral.state == CBManagerStatePoweredOn) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self setupPeripheral];
            [self startAdvertising];
        });
    }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
    didReceiveWriteRequests:(NSArray<CBATTRequest *> *)requests {
    for (CBATTRequest *request in requests) {
        if (request.value && request.value.length >= 21) {
            // PURE BLE: Just forward the raw packet data to C++
            if (self.packetReceivedCallback) {
                self.packetReceivedCallback(request.value);
            }
        }
        [peripheral respondToRequest:request withResult:CBATTErrorSuccess];
    }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
                         central:(CBCentral *)central
    didSubscribeToCharacteristic:(CBCharacteristic *)characteristic {
    if (![self.subscribedCentrals containsObject:central]) {
        [self.subscribedCentrals addObject:central];
    }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
                             central:(CBCentral *)central
    didUnsubscribeFromCharacteristic:(CBCharacteristic *)characteristic {
    [self.subscribedCentrals removeObject:central];
}

- (void)peripheralManagerDidStartAdvertising:(CBPeripheralManager *)peripheral
                                       error:(NSError *)error {
    // Advertising started successfully
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
            didAddService:(CBService *)service
                    error:(NSError *)error {
    // Service added successfully
}

// ============================================================================
// CBPeripheralDelegate - PURE BLE ONLY
// ============================================================================

- (void)peripheral:(CBPeripheral *)peripheral
    didDiscoverServices:(NSError *)error {
    for (CBService *service in peripheral.services) {
        if ([service.UUID isEqual:[CBUUID UUIDWithString:SERVICE_UUID]]) {
            [peripheral discoverCharacteristics:@[ [CBUUID UUIDWithString:CHARACTERISTIC_UUID] ]
                                     forService:service];
        }
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
    didDiscoverCharacteristicsForService:(CBService *)service
                                   error:(NSError *)error {
    for (CBCharacteristic *characteristic in service.characteristics) {
        if ([characteristic.UUID isEqual:[CBUUID UUIDWithString:CHARACTERISTIC_UUID]]) {
            [self.peripheralCharacteristics setObject:characteristic forKey:peripheral];
            [peripheral setNotifyValue:YES forCharacteristic:characteristic];
        }
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
    didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic
                              error:(NSError *)error {
    NSData *data = characteristic.value;
    if (!data || data.length < 21) {
        return;
    }
    
    // PURE BLE: Just forward the raw packet data to C++
    if (self.packetReceivedCallback) {
        self.packetReceivedCallback(data);
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
    didUpdateNotificationStateForCharacteristic:(CBCharacteristic *)characteristic
                                          error:(NSError *)error {
    // Notification state updated
}

// ============================================================================
// Private methods - PURE BLE ONLY
// ============================================================================

- (void)startScanning {
    if (self.centralManager.state == CBManagerStatePoweredOn) {
        NSDictionary *options = @{CBCentralManagerScanOptionAllowDuplicatesKey : @YES};
        [self.centralManager scanForPeripheralsWithServices:@[ [CBUUID UUIDWithString:SERVICE_UUID] ]
                                                   options:options];
    }
}

- (void)setupPeripheral {
    self.mutableCharacteristic = [[CBMutableCharacteristic alloc]
        initWithType:[CBUUID UUIDWithString:CHARACTERISTIC_UUID]
          properties:CBCharacteristicPropertyRead | CBCharacteristicPropertyWrite | 
                     CBCharacteristicPropertyWriteWithoutResponse | CBCharacteristicPropertyNotify
                value:nil
          permissions:CBAttributePermissionsReadable | CBAttributePermissionsWriteable];

    CBMutableService *service = [[CBMutableService alloc]
        initWithType:[CBUUID UUIDWithString:SERVICE_UUID]
             primary:YES];
    service.characteristics = @[ self.mutableCharacteristic ];

    [self.peripheralManager addService:service];
}

- (void)startAdvertising {
    if (self.peripheralManager.state == CBManagerStatePoweredOn) {
        NSString *localName = [self getLocalPeerId];
        NSDictionary *advertisementData = @{
            CBAdvertisementDataServiceUUIDsKey : @[ [CBUUID UUIDWithString:SERVICE_UUID] ],
            CBAdvertisementDataLocalNameKey : localName
        };
        [self.peripheralManager startAdvertising:advertisementData];
    }
}



@end 