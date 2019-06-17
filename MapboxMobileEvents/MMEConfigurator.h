#import <Foundation/Foundation.h>

@class MMEAPIClient;
@class MMEEventsConfiguration;

@protocol MMEConfiguratorDelegate <NSObject>

- (void)configurator:(id)updater didUpdate:(MMEEventsConfiguration *)configuration;

@end

#pragma mark -

@interface MMEConfigurator : NSObject

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithTimeInterval:(NSTimeInterval)timeInterval NS_DESIGNATED_INITIALIZER;
- (void)updateConfigurationFromAPIClient:(MMEAPIClient *)apiClient;

@property (nonatomic) NSTimeInterval timeInterval;
@property (nonatomic, weak) id <MMEConfiguratorDelegate> delegate;

@end
