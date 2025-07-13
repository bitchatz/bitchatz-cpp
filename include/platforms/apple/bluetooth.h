#pragma once

#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>

// Objective-C interface for Apple Bluetooth implementation - PURE BLE ONLY
// This header should ONLY be included by .mm or .m files
@interface AppleBluetooth : NSObject <CBCentralManagerDelegate, CBPeripheralManagerDelegate, CBPeripheralDelegate>

// Properties
@property(nonatomic, strong) CBCentralManager *centralManager;
@property(nonatomic, strong) CBPeripheralManager *peripheralManager;
@property(nonatomic, strong) CBMutableCharacteristic *mutableCharacteristic;
@property(nonatomic, strong) NSMutableArray *discoveredPeripherals;
@property(nonatomic, strong) NSMutableDictionary *connectedPeripherals;
@property(nonatomic, strong) NSMutableDictionary *peripheralCharacteristics;
@property(nonatomic, strong) NSMutableArray *subscribedCentrals;
@property(nonatomic, assign) BOOL ready;
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, strong) dispatch_queue_t bleQueue;
@property(nonatomic, strong) NSString *localPeerId;

// Callback properties - PURE BLE ONLY
@property(nonatomic, copy) void (^peerDisconnectedCallback)(NSString *);
@property(nonatomic, copy) void (^packetReceivedCallback)(NSData *);

// Initialization
- (instancetype)init;
- (BOOL)initialize;
- (BOOL)start;
- (void)stop;

// Packet sending - PURE BLE ONLY
- (BOOL)sendPacket:(NSData *)packetData;
- (BOOL)sendPacket:(NSData *)packetData toPeripheral:(CBPeripheral *)peripheral;
- (BOOL)sendPacket:(NSData *)packetData toPeer:(NSString *)peerId;

// State
- (BOOL)isReady;
- (NSString *)getLocalPeerId;
- (NSUInteger)getConnectedPeersCount;

// Callback setters - PURE BLE ONLY
- (void)setPeerDisconnectedCallback:(void (^)(NSString *peerId))callback;
- (void)setPacketReceivedCallback:(void (^)(NSData *packetData))callback;

// Constants
+ (NSString *)serviceUUID;
+ (NSString *)characteristicUUID;

@end