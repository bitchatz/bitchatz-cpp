#pragma once

#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>

// Objective-C interface for Apple Bluetooth implementation
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
@property(nonatomic, strong) NSString *localPeerID;

// Callback properties
@property(nonatomic, copy) void (^peerConnectedCallback)(NSString *);
@property(nonatomic, copy) void (^peerDisconnectedCallback)(NSString *);
@property(nonatomic, copy) void (^packetReceivedCallback)(NSData *);

// Initialization
- (instancetype)init;
- (BOOL)initialize;
- (BOOL)start;
- (void)stop;

// Packet sending
- (BOOL)sendPacket:(NSData *)packetData;
- (BOOL)sendPacket:(NSData *)packetData toPeripheral:(CBPeripheral *)peripheral;
- (BOOL)sendPacket:(NSData *)packetData toPeer:(NSString *)peerID;

// State
- (BOOL)isReady;
- (NSString *)getLocalPeerID;
- (void)setLocalPeerID:(NSString *)peerID;
- (NSUInteger)getConnectedPeersCount;

// Callback setters
- (void)setPeerDisconnectedCallback:(void (^)(NSString *peerID))callback;
- (void)setPacketReceivedCallback:(void (^)(NSData *packetData))callback;

// Constants
+ (NSString *)serviceUUID;
+ (NSString *)characteristicUUID;

@end
