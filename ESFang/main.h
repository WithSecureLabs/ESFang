//
//  Header.h
//  ESFang
//
//  Created by cmorley on 01/04/2020.
//  Copyright © 2020 ccs. All rights reserved.
//

#ifndef main_h
#define main_h

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <IOKit/kext/KextManager.h>
#import <Kernel/kern/cs_blobs.h>

#define KEY_SIGNATURE_CDHASH @"cdHash"
#define KEY_SIGNATURE_FLAGS @"csFlags"
#define KEY_SIGNATURE_IDENTIFIER @"signatureIdentifier"
#define KEY_SIGNATURE_TEAM_IDENTIFIER @"teamIdentifier"
#define KEY_SIGNATURE_PLATFORM_BINARY @"isPlatformBinary"

// Event Class for events
@class SecurityEvent;

// Typedef for event handling callback function
typedef void (^EventCallbackBlock)(SecurityEvent* _Nonnull);

@interface Inspecter : NSObject
-(BOOL)start:(EventCallbackBlock _Nonnull)callback :(NSArray *_Nullable)userProvidedEvents :(NSNumber *_Nullable)argumentFlag;
-(BOOL)stop;
@end

@interface SecurityEvent : NSObject

// Properties. These properties will need to be serialized into JSON
@property NSNumber* _Nonnull pid;
@property NSDate* _Nonnull timestamp;
@property NSString* _Nonnull hostname;
@property NSNumber* _Nonnull uid;
@property NSString* _Nonnull user;
@property NSString* _Nonnull type;
@property NSMutableDictionary* _Nonnull metadata;
//@property NSPredicate* _Nullable eventFilter;
@property NSString* _Nonnull eventGroup;

// Initialization method for all events
-(id _Nullable)init:(es_message_t* _Nonnull)message;
// helper function written by Patrick Wardle to extract arguments for process events
-(void)extractArgs:(es_events_t *_Nonnull)event;
// helper function written by Patrick Wardle to extract signing info in Process events
-(void)extractSigningInfo:(es_process_t *_Nonnull)process forOriginProcess:(bool)forOriginProcess;
// helper function written by Patrick Wardle to extract file path information for file events
-(void)extractPaths:(es_message_t*_Nonnull)message;

// helper function to handle events in general
-(void)handleProcessEventData:(es_process_t *_Nonnull)process;
-(void)extractOriginProcessDataForEvent:(es_process_t *_Nonnull)process;
-(void)extractEnvironmentVariablesForProcess:(es_event_exec_t *_Nonnull)process;
-(void)handleProcessChangeDirEventData:(es_event_chdir_t *_Nonnull)changeDir;
-(void)handleProcessChangeRootEventDagta:(es_event_chroot_t *_Nonnull)chroot;
-(void)handleProcessSignalEventData:(es_event_signal_t *_Nonnull)signalSent;
-(void)handleProcessInformationRequestEventData:(es_event_proc_check_t *_Nonnull)procCheck;
-(void)handleGetTaskEventData:(es_event_get_task_t *_Nonnull)task;
-(void)handleMMapEventData:(es_event_mmap_t *_Nonnull)mmap;
-(void)handleMprotectEventData:(es_event_mprotect_t *_Nonnull)mProtect;
-(void)handleKextEventData:(es_message_t *_Nonnull)kext;
-(void)handleSetExtattrEventData:(es_event_setextattr_t *_Nonnull)extattr;
-(void)handleSetAttrlistEventData:(es_event_setattrlist_t *_Nonnull)attr;
-(void)handleGetAttrlistEventData:(es_event_getattrlist_t *_Nonnull)attr;
-(void)handleGetExtendedAttributeEventData:(es_event_getextattr_t *_Nonnull)getExt;
-(void)handleListExtendedAttributes:(es_event_listextattr_t *_Nonnull)listExt;
-(void)handleDeleteExtendedAttributeEventData:(es_event_deleteextattr_t *_Nonnull)deleteExt;
-(void)handleSetModeEventData:(es_event_setmode_t *_Nonnull)modeSet;
-(void)handleSetFileAclEventData:(es_event_setacl_t *_Nonnull)setAcl;
-(void)handleUpdateTimesEventDAta:(es_event_utimes_t *_Nonnull)utime;
-(void)handleReadDirectoryEventData:(es_event_readdir_t *_Nonnull)readdir;
-(void)handleFileSystemGetPathEventData:(es_event_fsgetpath_t *_Nonnull)fsgetpath;
-(void)handleGetFileStatusEventData:(es_event_stat_t *_Nonnull)stat;
-(void)handleSetFlagsEventData:(es_event_setflags_t *_Nonnull)setFlags;
-(void)handleSetOwnerEventData:(es_event_setowner_t *_Nonnull)owner;
//-(void)extractFileOpenFlags:(es_event_open_t *_Nonnull)open;
-(void)handleFileDataExchange:(es_event_exchangedata_t *_Nonnull)fileExchange;
-(void)handleBindingSocketEventData:(es_message_t *_Nonnull)message;
-(void)handleConnectingSocketEventData:(es_message_t *_Nonnull)message;
-(void)handlePsuedoterminalClosureEvent:(es_event_pty_close_t *_Nonnull)psuedoTerm;
-(void)handlePsuedoterminalGrantEvent:(es_event_pty_grant_t *_Nonnull)psuedoTerm;
-(void)handleDeviceMountEventData:(es_event_mount_t *_Nonnull)deviceMount;
-(void)handleDeviceUnmountEventData:(es_event_unmount_t *_Nonnull)deviceMount;
-(void)handleFileProviderMaterializeEventData:(es_event_file_provider_materialize_t *_Nonnull)fileProviderM;
-(void)handleFileProviderUpdateEventData:(es_event_file_provider_update_t *_Nonnull)fileProviderU;
-(void)handleFileTruncationEventData:(es_event_truncate_t *_Nonnull)truncation;
-(void)handleFileLookupEventData:(es_event_lookup_t *_Nonnull)lookup;
-(void)handleFileAccessCheckEventDatya:(es_event_access_t *_Nonnull)access;

-(NSString*_Nonnull)nsDateToString;


@end

#endif /* Header_h */
