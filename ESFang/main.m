//
//  main.m
//  ESFang
//
//  Created by cmorley on 01/04/2020.
//  Copyright © 2020 cmorley. All rights reserved.
//
// Shout out to the following projects who paved the way:
//  https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba
//  https://bitbucket.org/xorrior/appmon/src/master/
//  https://github.com/objective-see/ProcessMonitor
//


/*
    PURPOSE
    *******
    This project is to create a working local ESF data tapping tool that can be used for both human analysis and piping data to an EDR agent via json at a later data when requied. The use of this tool will allow researchers to fill in gaps that are currently apparent in the data acquisition stages using old openBSD tools or exiting ESF data tools. From using this tool, researchers will be able to have full visibility over the security logged data of the host and therefore be able to better categorize their analysis and create detection criteria more appropriate to the offensive actions behaviour.
 
    This tool also allows a "hacky" method to continually expand our access to the data stream on a case by case basis. This will allow the development pf detection rulse to be based on data that we know is available within the ESF.
 
    Finally, the use of this tool will allow research to be conducted both on filtered (due to overhead) data from the future agent and the raw ESF data stream conducted within a testing machines. This will allow a full analysis of output data from the subsystem and potentially circumvent situations where detection has been missed due to system required filtering. In these situations adaptaitons can be made for the data acquisition if the value for the deteciton is high enough.
 
    NOTES
    *****
    - File closure event are exremely prevelant during testing and make up the vast amount of events that are being processed. Additionally on inspection it can be seen that they are the cause of the OS file descriptor load issue which cases the recurring error 24 due to too many files being accessed/monitored simutaiously.
    - Data loss due to overload of the ESF client object is a prevailing issue, time for multi-threading has been deemed too extensive. As such case by case adaptation of event ingestion implemented.
 */

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <bsm/libbsm.h>
#import <mach/mach_time.h>
#import "launchdXPC.h"
#import <CommonCrypto/CommonDigest.h>
#include <libproc.h>
#include <dlfcn.h>
#include "main.h"

#define NSLog(FORMAT, ...) fprintf( stderr, "%s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String] );

es_client_t* endpointClient = nil;


// GLOBAL EVENTS SUBSCRIPTION TO HANDLE
es_event_type_t events[] = {
    //HANDLED
    // Process/Applicaiton events
    ES_EVENT_TYPE_NOTIFY_GET_TASK       // Identify that a process is retrieving task port for another process
    , ES_EVENT_TYPE_NOTIFY_EXEC         // exexcution of an image/process
    , ES_EVENT_TYPE_NOTIFY_FORK         // forking another process
    , ES_EVENT_TYPE_NOTIFY_EXIT         // process is exiting
    , ES_EVENT_TYPE_NOTIFY_CHDIR        // provides information on process directory change
    , ES_EVENT_TYPE_NOTIFY_CHROOT       // provides inforamtion on new root directory for process when it changes during operation
    , ES_EVENT_TYPE_NOTIFY_SIGNAL       // signal being sent from one process to another
    , ES_EVENT_TYPE_NOTIFY_PROC_CHECK   // retrieval of process information *** MORE WORK NEEDED TO CROSS REFERENCE FLAVOR ***
    // File operations
    , ES_EVENT_TYPE_NOTIFY_CREATE       // creation of a file
    , ES_EVENT_TYPE_NOTIFY_DUP          // duplication of a file descriptor
    , ES_EVENT_TYPE_NOTIFY_CLOSE        // closure of a file
    , ES_EVENT_TYPE_NOTIFY_WRITE        // write of a file
    , ES_EVENT_TYPE_NOTIFY_RENAME       // rename a file
    , ES_EVENT_TYPE_NOTIFY_OPEN         // open a file
    , ES_EVENT_TYPE_NOTIFY_CLONE        // clone/copy of a file
    , ES_EVENT_TYPE_NOTIFY_TRUNCATE     // file truncation event
    , ES_EVENT_TYPE_NOTIFY_LOOKUP       // file lookup event
    , ES_EVENT_TYPE_NOTIFY_ACCESS       // check file access permissions
    , ES_EVENT_TYPE_NOTIFY_FCNTL        // file descriptor modified
    , ES_EVENT_TYPE_NOTIFY_LINK         // link file created
    , ES_EVENT_TYPE_NOTIFY_UNLINK       // destroy link file
    , ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA // file exchange between files
    , ES_EVENT_TYPE_NOTIFY_READLINK
    // File system operations
    , ES_EVENT_TYPE_NOTIFY_MOUNT
    , ES_EVENT_TYPE_NOTIFY_UNMOUNT
    // Socket operations
    , ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT // socket connection established
    , ES_EVENT_TYPE_NOTIFY_UIPC_BIND    // create socket bind file/dir
    // Kernel extensions
    , ES_EVENT_TYPE_NOTIFY_KEXTLOAD     // loading of a kernel extension (depreciated)
    , ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD   // unloading of a kernel extension (depreciated)
    // Device connection
    , ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN   // open an iokit device - hardware device and drivers
    // Meta data tampering
    , ES_EVENT_TYPE_NOTIFY_SETATTRLIST  // setting attributes of a file
    , ES_EVENT_TYPE_NOTIFY_GETATTRLIST  // getting of attributes list of a file
    , ES_EVENT_TYPE_NOTIFY_GETEXTATTR   // get an extended attribute from file
    , ES_EVENT_TYPE_NOTIFY_LISTEXTATTR  // get multiple extended attributes from file
    , ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR    // Delete extended file attribute
    , ES_EVENT_TYPE_NOTIFY_SETOWNER     // setting the owner of a file
    , ES_EVENT_TYPE_NOTIFY_SETEXTATTR   // setting extended attributes of file
    , ES_EVENT_TYPE_NOTIFY_SETFLAGS     // File access flags set or changed
    , ES_EVENT_TYPE_NOTIFY_SETMODE      // Setting of a files mode
    , ES_EVENT_TYPE_NOTIFY_SETACL       // set file access control list *** NEEDS TESTING ***
    , ES_EVENT_TYPE_NOTIFY_UTIMES       // setting of file last accessed and modified time stamps
    , ES_EVENT_TYPE_NOTIFY_READDIR      // Reading of a file system directory
    , ES_EVENT_TYPE_NOTIFY_FSGETPATH    // get file system path
    , ES_EVENT_TYPE_NOTIFY_STAT         // get file status
    // Memory access/change events
    , ES_EVENT_TYPE_NOTIFY_MMAP         // a process is mapping a file into memory
    , ES_EVENT_TYPE_NOTIFY_MPROTECT     // protection for a memory section is set OR changed
    // Psuedoterminal events
    , ES_EVENT_TYPE_NOTIFY_PTY_GRANT
    , ES_EVENT_TYPE_NOTIFY_PTY_CLOSE
    // File provider events
    , ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE
    , ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE
    // System time event
    , ES_EVENT_TYPE_NOTIFY_SETTIME      // set system time
};

// GLOBAL EVENTS SUBSCRIPTION TO HANDLE
es_event_type_t procEvents[] = {
    //HANDLED
    // Process/Applicaiton events
    //ES_EVENT_TYPE_NOTIFY_GET_TASK       // Identify that a process is retrieving task port for another process *HIGH VOLUME EVENT TYPE*
     ES_EVENT_TYPE_NOTIFY_EXEC         // exexcution of an image/process
    , ES_EVENT_TYPE_NOTIFY_FORK         // forking another process
    , ES_EVENT_TYPE_NOTIFY_EXIT         // process is exiting
    , ES_EVENT_TYPE_NOTIFY_CHDIR        // provides information on process directory change
    , ES_EVENT_TYPE_NOTIFY_CHROOT       // provides inforamtion on new root directory for process when it changes during operation
    , ES_EVENT_TYPE_NOTIFY_SIGNAL       // signal being sent from one process to another
    // , ES_EVENT_TYPE_NOTIFY_PROC_CHECK   // retrieval of process information *HIGH VOLUME EVENT TYPE*
};
es_event_type_t fileEvents[] = {
    // File operations
    ES_EVENT_TYPE_NOTIFY_CREATE       // creation of a file
    , ES_EVENT_TYPE_NOTIFY_DUP          // duplication of a file descriptor
    //, ES_EVENT_TYPE_NOTIFY_CLOSE        // closure of a file *HIGH VOLUME EVENT TYPE*
    , ES_EVENT_TYPE_NOTIFY_WRITE        // write of a file
    , ES_EVENT_TYPE_NOTIFY_RENAME       // rename a file
    , ES_EVENT_TYPE_NOTIFY_OPEN         // open a file
    , ES_EVENT_TYPE_NOTIFY_CLONE        // clone/copy of a file
    , ES_EVENT_TYPE_NOTIFY_TRUNCATE     // file truncation event
    //, ES_EVENT_TYPE_NOTIFY_LOOKUP       // file lookup event
    //, ES_EVENT_TYPE_NOTIFY_ACCESS       // check file access permissions *HIGH VOLUME EVENT TYPE*
    , ES_EVENT_TYPE_NOTIFY_FCNTL        // file descriptor modified
    , ES_EVENT_TYPE_NOTIFY_LINK         // link file created
    , ES_EVENT_TYPE_NOTIFY_UNLINK       // destroy link file
    , ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA // file exchange between files
    , ES_EVENT_TYPE_NOTIFY_READLINK
};
es_event_type_t mountEvents[] = {
    // File system operations
    ES_EVENT_TYPE_NOTIFY_MOUNT
    , ES_EVENT_TYPE_NOTIFY_UNMOUNT
};
es_event_type_t socketEvents[] = {
    // Socket operations
    ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT // socket connection established
    , ES_EVENT_TYPE_NOTIFY_UIPC_BIND    // create socket bind file/dir
};
es_event_type_t kextEvents[] = {
    // Kernel extensions
    ES_EVENT_TYPE_NOTIFY_KEXTLOAD     // loading of a kernel extension (depreciated)
    , ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD   // unloading of a kernel extension (depreciated)
};
es_event_type_t iokitEvents[] = {
    // Device connection
    ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN   // open an iokit device - hardware device and drivers
};
es_event_type_t filemetaEvents[] = {
    // Meta data tampering
    ES_EVENT_TYPE_NOTIFY_SETATTRLIST  // setting attributes of a file
    , ES_EVENT_TYPE_NOTIFY_GETATTRLIST  // getting of attributes list of a file
    , ES_EVENT_TYPE_NOTIFY_GETEXTATTR   // get an extended attribute from file
    , ES_EVENT_TYPE_NOTIFY_LISTEXTATTR  // get multiple extended attributes from file
    , ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR    // Delete extended file attribute
    , ES_EVENT_TYPE_NOTIFY_SETOWNER     // setting the owner of a file
    , ES_EVENT_TYPE_NOTIFY_SETEXTATTR   // setting extended attributes of file
    , ES_EVENT_TYPE_NOTIFY_SETFLAGS     // File access flags set or changed
    , ES_EVENT_TYPE_NOTIFY_SETMODE      // Setting of a files mode
    , ES_EVENT_TYPE_NOTIFY_SETACL       // set file access control list *** NEEDS TESTING ***
    , ES_EVENT_TYPE_NOTIFY_UTIMES       // setting of file last accessed and modified time stamps
    , ES_EVENT_TYPE_NOTIFY_READDIR      // Reading of a file system directory
    // , ES_EVENT_TYPE_NOTIFY_FSGETPATH    // get file system path *HIGH VOLUME EVENT TYPE*
    // , ES_EVENT_TYPE_NOTIFY_STAT         // get file status *HIGH VOLUME EVENT TYPE*
};
es_event_type_t memoryEvents[] = {
    // Memory access/change events
    ES_EVENT_TYPE_NOTIFY_MMAP         // a process is mapping a file into memory
    , ES_EVENT_TYPE_NOTIFY_MPROTECT     // protection for a memory section is set OR changed
};
es_event_type_t pseudoterminalEvents[] = {
    // Psuedoterminal events
    ES_EVENT_TYPE_NOTIFY_PTY_GRANT
    , ES_EVENT_TYPE_NOTIFY_PTY_CLOSE
};
es_event_type_t fileproviderEvents[] = {
    // File provider events
    ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE
    , ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE
};
es_event_type_t systemtimeEvents[] = {
    // System time event
    ES_EVENT_TYPE_NOTIFY_SETTIME      // set system time
};
    
NSString* socketTypeToString(int socketType)
{
    switch(socketType) {
        case 1:
            return @"SOCK_STREAM";
        case 2 :
            return @"SOCK_DGRAM";
        case 3 :
            return @"SOCK_RAW";
        case 4 :
            return @"SOCK_RDM";
        case 5 :
            return @"SOCK_SEQPACKET";
        default :
            return @"SOCK_UNKNOWN";
    }
}

NSString* socketDomainToString(int socketType)
{
    switch(socketType) {
        // Local to hosty (pipes)
        case 1 :
            return @"PF_LOCAL/PF_UNIX - AF_UNIX";
        case 2 :
            return @"PF_INET - AF_INET";
        case 17 :
            return @"PF_ROUTE - AF_ROUTE";
        // Network driver raw access
        case 27 :
            return @"PF_NDRV - AF_NDRV";
        // Internal key management function
        case 29 :
            return @"PF_KEY - pseudo_AF_KEY";
        case 30 :
            return @"PF_INET6 - AF_INET6";
        // Kernel event message
        case 32 :
            return @"PF_SYSTEM - AF_SYSTEM";
        default :
            return @"SOCK_UNKNOWN";
    }
}


NSString* convertStringToken(es_string_token_t* stringToken)
{
    //string
    NSString* string = nil;
    
    //sanity check(s)
    if( (NULL == stringToken) ||
        (NULL == stringToken->data) ||
        (stringToken->length <= 0) )
    {
        //bail
        goto bail;
    }
        
    //convert to data, then to string
    string = [[NSString alloc] initWithBytes:stringToken->data length:stringToken->length encoding:NSUTF8StringEncoding];
    
    bail:
    
        return string;
}


// Convert the event type to a string
NSString* event_type_str(const es_event_type_t event_type) {
    switch(event_type) {
        case ES_EVENT_TYPE_NOTIFY_GET_TASK: return @"ES_EVENT_TYPE_NOTIFY_GET_TASK";
        case ES_EVENT_TYPE_NOTIFY_MMAP: return @"ES_EVENT_TYPE_NOTIFY_MMAP";
        case ES_EVENT_TYPE_NOTIFY_MPROTECT: return @"ES_EVENT_TYPE_NOTIFY_MPROTECT";
        case ES_EVENT_TYPE_NOTIFY_EXEC: return @"ES_EVENT_NOTIFY_EXEC";
        case ES_EVENT_TYPE_NOTIFY_FORK: return @"ES_EVENT_NOTIFY_FORK";
        case ES_EVENT_TYPE_NOTIFY_EXIT: return @"ES_EVENT_NOTIFY_EXIT";
        case ES_EVENT_TYPE_NOTIFY_CHDIR: return @"ES_EVENT_TYPE_NOTIFY_CHDIR";
        case ES_EVENT_TYPE_NOTIFY_CHROOT: return @"ES_EVENT_TYPE_NOTIFY_CHROOT";
        case ES_EVENT_TYPE_NOTIFY_SIGNAL: return @"ES_EVENT_TYPE_NOTIFY_SIGNAL";
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK: return @"ES_EVENT_TYPE_NOTIFY_PROC_CHECK";
        case ES_EVENT_TYPE_NOTIFY_CREATE: return @"ES_EVENT_TYPE_NOTIFY_CREATE";
        case ES_EVENT_TYPE_NOTIFY_DUP: return @"ES_EVENT_TYPE_NOTIFY_DUP";
        case ES_EVENT_TYPE_NOTIFY_CLOSE: return @"ES_EVENT_TYPE_NOTIFY_CLOSE";
        case ES_EVENT_TYPE_NOTIFY_WRITE: return @"ES_EVENT_TYPE_NOTIFY_WRITE";
        case ES_EVENT_TYPE_NOTIFY_RENAME: return @"ES_EVENT_TYPE_NOTIFY_RENAME";
        case ES_EVENT_TYPE_NOTIFY_OPEN: return @"ES_EVENT_TYPE_NOTIFY_OPEN";
        case ES_EVENT_TYPE_NOTIFY_CLONE: return @"ES_EVENT_TYPE_NOTIFY_CLONE";
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE: return @"ES_EVENT_TYPE_NOTIFY_TRUNCATE";
        case ES_EVENT_TYPE_NOTIFY_LOOKUP: return @"ES_EVENT_TYPE_NOTIFY_LOOKUP";
        case ES_EVENT_TYPE_NOTIFY_ACCESS: return @"ES_EVENT_TYPE_NOTIFY_ACCESS";
        case ES_EVENT_TYPE_NOTIFY_FCNTL: return @"ES_EVENT_TYPE_NOTIFY_FCNTL";
        case ES_EVENT_TYPE_NOTIFY_LINK: return @"ES_EVENT_TYPE_NOTIFY_LINK";
        case ES_EVENT_TYPE_NOTIFY_UNLINK: return @"ES_EVENT_TYPE_NOTIFY_UNLINK";
        case ES_EVENT_TYPE_NOTIFY_READLINK: return @"ES_EVENT_TYPE_NOTIFY_READLINK";
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: return @"ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA";
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: return @"ES_EVENT_TYPE_NOTIFY_KEXTLOAD";
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD: return @"ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD";
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: return @"ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN";
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST: return @"ES_EVENT_TYPE_NOTIFY_SETATTRLIST";
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST: return @"ES_EVENT_TYPE_NOTIFY_GETATTRLIST";
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR: return @"ES_EVENT_TYPE_NOTIFY_GETEXTATTR";
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR: return @"ES_EVENT_TYPE_NOTIFY_LISTEXTATTR";
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR: return @"ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR";
        case ES_EVENT_TYPE_NOTIFY_SETOWNER: return @"ES_EVENT_TYPE_NOTIFY_SETOWNER";
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: return @"ES_EVENT_TYPE_NOTIFY_SETEXTATTR";
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS: return @"ES_EVENT_TYPE_NOTIFY_SETFLAGS";
        case ES_EVENT_TYPE_NOTIFY_SETMODE: return @"ES_EVENT_TYPE_NOTIFY_SETMODE";
        case ES_EVENT_TYPE_NOTIFY_SETACL: return @"ES_EVENT_TYPE_NOTIFY_SETACL";
        case ES_EVENT_TYPE_NOTIFY_UTIMES: return @"ES_EVENT_TYPE_NOTIFY_UTIMES";
        case ES_EVENT_TYPE_NOTIFY_READDIR: return @"ES_EVENT_TYPE_NOTIFY_READDIR";
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH: return @"ES_EVENT_TYPE_NOTIFY_FSGETPATH";
        case ES_EVENT_TYPE_NOTIFY_STAT: return @"ES_EVENT_TYPE_NOTIFY_STAT";
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: return @"ES_EVENT_TYPE_NOTIFY_UIPC_BIND";
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: return @"ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT";
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT: return @"ES_EVENT_TYPE_NOTIFY_PTY_GRANT";
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE: return @"ES_EVENT_TYPE_NOTIFY_PTY_CLOSE";
        case ES_EVENT_TYPE_NOTIFY_MOUNT: return @"ES_EVENT_TYPE_NOTIFY_MOUNT";
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT: return @"ES_EVENT_TYPE_NOTIFY_UNMOUNT";
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE: return @"ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE";
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE: return @"ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE";
        case ES_EVENT_TYPE_NOTIFY_SETTIME: return @"ES_EVENT_TYPE_NOTIFY_SETTIME";
                
        default: return @"EVENT_TYPE_UNKNOWN";
    }
}

es_event_type_t id_event_type(int event_id) {
    switch(event_id) {
        case 1 : return ES_EVENT_TYPE_NOTIFY_GET_TASK;
        case 2: return ES_EVENT_TYPE_NOTIFY_EXEC;
        case 3: return ES_EVENT_TYPE_NOTIFY_FORK;
        case 4: return ES_EVENT_TYPE_NOTIFY_EXIT;
        case 5: return ES_EVENT_TYPE_NOTIFY_CHDIR;
        case 6: return ES_EVENT_TYPE_NOTIFY_CHROOT;
        case 7: return ES_EVENT_TYPE_NOTIFY_SIGNAL;
        case 8 : return ES_EVENT_TYPE_NOTIFY_PROC_CHECK;
        // File operations
        case 9: return ES_EVENT_TYPE_NOTIFY_CREATE;
        case 10: return ES_EVENT_TYPE_NOTIFY_DUP;
        case 11: return ES_EVENT_TYPE_NOTIFY_WRITE;
        case 12: return ES_EVENT_TYPE_NOTIFY_RENAME;
        case 13: return ES_EVENT_TYPE_NOTIFY_OPEN;
        case 14: return ES_EVENT_TYPE_NOTIFY_CLONE;
        case 15: return ES_EVENT_TYPE_NOTIFY_TRUNCATE;
        case 16: return ES_EVENT_TYPE_NOTIFY_LOOKUP;
        case 17: return ES_EVENT_TYPE_NOTIFY_ACCESS;
        case 18: return ES_EVENT_TYPE_NOTIFY_FCNTL;
        case 19: return ES_EVENT_TYPE_NOTIFY_LINK;
        case 20: return ES_EVENT_TYPE_NOTIFY_UNLINK;
        case 21: return ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA;
        case 22: return ES_EVENT_TYPE_NOTIFY_READLINK;
        // File system operations
        case 23: return ES_EVENT_TYPE_NOTIFY_MOUNT;
        case 24: return ES_EVENT_TYPE_NOTIFY_UNMOUNT;
        // Socket operations
        case 25: return ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT;
        case 26: return ES_EVENT_TYPE_NOTIFY_UIPC_BIND;
        // Kernel extensions
        case 27: return ES_EVENT_TYPE_NOTIFY_KEXTLOAD;
        case 28: return ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD;
        // Device connection
        case 29: return ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN;
        // Meta data tampering
        case 30: return ES_EVENT_TYPE_NOTIFY_SETATTRLIST;
        case 31: return ES_EVENT_TYPE_NOTIFY_GETATTRLIST;
        case 32: return ES_EVENT_TYPE_NOTIFY_GETEXTATTR;
        case 34: return ES_EVENT_TYPE_NOTIFY_LISTEXTATTR;
        case 35: return ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR;
        case 36: return ES_EVENT_TYPE_NOTIFY_SETOWNER;
        case 37: return ES_EVENT_TYPE_NOTIFY_SETEXTATTR;
        case 38: return ES_EVENT_TYPE_NOTIFY_SETFLAGS;
        case 39: return ES_EVENT_TYPE_NOTIFY_SETMODE;
        case 40: return ES_EVENT_TYPE_NOTIFY_SETACL;
        case 41: return ES_EVENT_TYPE_NOTIFY_UTIMES;
        case 42: return ES_EVENT_TYPE_NOTIFY_READDIR;
        case 43: return ES_EVENT_TYPE_NOTIFY_FSGETPATH;
        case 44: return ES_EVENT_TYPE_NOTIFY_STAT;
        // Memory access/change events
        case 45: return ES_EVENT_TYPE_NOTIFY_MMAP;
        case 46: return ES_EVENT_TYPE_NOTIFY_MPROTECT;
        // Psuedoterminal events
        case 47: return  ES_EVENT_TYPE_NOTIFY_PTY_GRANT;
        case 48: return ES_EVENT_TYPE_NOTIFY_PTY_CLOSE;
        // File provider events
        case 49: return ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE;
        case 50: return ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE;
        // System time event
        case 51: return ES_EVENT_TYPE_NOTIFY_SETTIME;
        case 52: return ES_EVENT_TYPE_NOTIFY_CLOSE;
                
        default: return ES_EVENT_TYPE_LAST;
    }
}

// Implement LaunchXPC code to circumvent the PPID issues being encountered
NSDictionary* getSubmittedByInfo(pid_t pid) {
    
    // init submittedby dict
    NSMutableDictionary *submittedby = [[NSMutableDictionary alloc] init];
    
    // get proc_info via launchdXPCb
    NSDictionary* proc_info = getProcessInfo(pid);
    
    // stop here if no result from proc_info
    if (proc_info == NULL) {
        return NULL;
    }
    
    //get path from proc_info
    NSString *submitted_by_path = proc_info[@"path"];
            
    // return name and pid if proc_info contains submitted by info
    if ([submitted_by_path containsString:@"submitted"]) {
            
            //split path into array
            NSString *sep = @".() ";
            NSCharacterSet *set = [NSCharacterSet characterSetWithCharactersInString:sep];
            NSArray *temp=[submitted_by_path componentsSeparatedByCharactersInSet:set];
            NSString *submitted_by_name = [temp objectAtIndex:3];
            NSString *submitted_by_pid = [temp objectAtIndex:4];
            [submittedby setValue:[NSString stringWithString:submitted_by_name] forKey:@"name"];
            [submittedby setValue:[NSString stringWithString:submitted_by_pid] forKey:@"pid"];
    // return plist if no submitted by info
    }else {
            [submittedby setValue:[NSString stringWithString:submitted_by_path] forKey:@"path"];

    }

    return submittedby;

}

NSString* getParentInfo(pid_t ppid)
{
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(ppid, pathbuf, sizeof(pathbuf));
    return [NSString stringWithFormat:@"%s", pathbuf];
}

pid_t getRealParentProcessId(pid_t pid)
{
    typedef pid_t (*pidResolver)(pid_t pid);
    pidResolver resolver = dlsym(RTLD_NEXT, "responsibility_get_pid_responsible_for_pid");
    pid_t trueParentPid = resolver(pid);
    return trueParentPid;
}


@implementation Inspecter : NSObject
// Monitoring
-(BOOL)start:(EventCallbackBlock)callback :(NSArray *)userProvidedEventsList :(NSNumber *)argumentType
{
    BOOL started = NO;
     //result
    es_new_client_result_t result = 0;
    
    @synchronized (self)
    {
        result = es_new_client(&endpointClient, ^(es_client_t *client, const es_message_t *message){
            
            /*
            NSNumber *hack_ppid = [NSNumber numberWithInt:message->process->ppid];
            NSNumber *hack_pid = [NSNumber numberWithInt:audit_token_to_pid(message->process->audit_token)];
            NSString *test_string = convertStringToken(&message->process->executable->path);
            NSString *test_ppath = [NSString stringWithString:getParentInfo(message->process->ppid)];
            NSNumber *tester = [NSNumber numberWithInt:13690];
            NSString *tester_bin_name = @"/tester.macho";
            
            // Hacky capture
            if(hack_ppid == tester || hack_pid == tester || [test_string containsString:tester_bin_name] || [test_ppath containsString:tester_bin_name]){
                
            //if([test_string containsString:tester_bin_name] || [test_ppath containsString:tester_bin_name]){
            */
             
            
                SecurityEvent *newEvent = nil;
                newEvent = [[SecurityEvent alloc] init:(es_message_t *_Nonnull)message];
                
                if (nil != newEvent) {
                    callback(newEvent);
                }
            /*}  else {
                uint32_t fflags = 0xffffffff;
                es_respond_flags_result(client, message, fflags, true);
                const char *literlPath = [convertStringToken(&message->process->executable->path) UTF8String];
                es_return_t res = es_mute_path_literal(client, literlPath);
                if (res != ES_RETURN_SUCCESS){
                    NSLog(@"mute failed: %@", res);
                } else {
                    NSLog(@"process muted: %@", convertStringToken(&message->process->executable->path));
                }
            }*/
            
        });
        
        
        //error?
        if(ES_NEW_CLIENT_RESULT_SUCCESS != result)
        {
            NSLog(@"ERROR: es_new_client() failed with %d", result);
            goto bail;
        }
        
        if(ES_CLEAR_CACHE_RESULT_SUCCESS != es_clear_cache(endpointClient))
        {
            //err msg
            NSLog(@"ERROR: es_clear_cache() failed");
            
            //bail
            goto bail;
        }
        
        //subscribe
        if(argumentType == NULL)
        {
            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, events, sizeof(*events)/sizeof(events[0])))
            {
                //err msg
                NSLog(@"ERROR: es_subscribe() failed");
                
                //bail
                goto bail;
            }
        } else {
            if([argumentType intValue] == 1){
                for(NSNumber *entry in userProvidedEventsList)
                {
                    es_event_type_t tempArray[] = {id_event_type([entry intValue])};
                    if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, tempArray, sizeof(tempArray)/sizeof(tempArray[0])))
                    {
                        //err msg
                        NSLog(@"ERROR: es_subscribe() failed");
                        
                        //bail
                        goto bail;
                    } else {
                        NSLog(@"Subscribed to event type : %@", event_type_str(tempArray[0]));
                    }
                }
            } else if ([argumentType intValue] == 2){
                for(NSNumber *entry in userProvidedEventsList)
                {
                    switch([entry intValue]) {
                        case 1:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, procEvents, sizeof(procEvents)/sizeof(procEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Process events");
                            }
                            break;
                        case 2:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, fileEvents, sizeof(fileEvents)/sizeof(fileEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : File events");
                            }
                            break;
                        case 3:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, mountEvents, sizeof(mountEvents)/sizeof(mountEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Mount events");
                            }
                            break;
                        case 4:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, socketEvents, sizeof(socketEvents)/sizeof(socketEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Socket events");
                            }
                            break;
                        case 5:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, kextEvents, sizeof(kextEvents)/sizeof(kextEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Kernel Extension events");
                            }
                            break;
                        case 6:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, iokitEvents, sizeof(iokitEvents)/sizeof(iokitEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Iokit events");
                            }
                            break;
                        case 7:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, filemetaEvents, sizeof(filemetaEvents)/sizeof(filemetaEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : File Metadata events");
                            }
                            break;
                        case 8:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, memoryEvents, sizeof(memoryEvents)/sizeof(memoryEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Memory events");
                            }
                            break;
                        case 9:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, pseudoterminalEvents, sizeof(pseudoterminalEvents)/sizeof(pseudoterminalEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Pseudo Terminal events");
                            }
                            break;
                        case 10:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, fileproviderEvents, sizeof(fileproviderEvents)/sizeof(fileproviderEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : File Provider events");
                            }
                            break;
                        case 11:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, systemtimeEvents, sizeof(systemtimeEvents)/sizeof(systemtimeEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : System Time events");
                            }
                            break;
                        default:
                            NSLog(@"Tried to subscribe to unknown event group, terminating!");
                            exit(1);
                            
                    }
                    
                }
            } else if ([argumentType intValue] == 3){
                NSMutableDictionary *config = userProvidedEventsList[0];
                NSArray *idsList = config[@"ids"];
                NSArray *groupList = config[@"groups"];
                if (groupList.count == 0 && idsList.count == 0){
                    NSLog(@"Config file has no options set, terminating program!");
                    exit(1);
                }
                for(NSNumber *entry in idsList)
                {
                    es_event_type_t tempArray[] = {id_event_type([entry intValue])};
                    if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, tempArray, sizeof(tempArray)/sizeof(tempArray[0])))
                    {
                        //err msg
                        NSLog(@"ERROR: es_subscribe() failed");
                        
                        //bail
                        goto bail;
                    } else {
                        NSLog(@"Subscribed to event type : %@", event_type_str(tempArray[0]));
                    }
                }
                for(NSNumber *entry in groupList)
                {
                    switch([entry intValue]) {
                        case 1:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, procEvents, sizeof(procEvents)/sizeof(procEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Process events");
                            }
                            break;
                        case 2:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, fileEvents, sizeof(fileEvents)/sizeof(fileEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : File events");
                            }
                            break;
                        case 3:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, mountEvents, sizeof(mountEvents)/sizeof(mountEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Mount events");
                            }
                            break;
                        case 4:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, socketEvents, sizeof(socketEvents)/sizeof(socketEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Socket events");
                            }
                            break;
                        case 5:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, kextEvents, sizeof(kextEvents)/sizeof(kextEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Kernel Extension events");
                            }
                            break;
                        case 6:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, iokitEvents, sizeof(iokitEvents)/sizeof(iokitEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Iokit events");
                            }
                            break;
                        case 7:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, filemetaEvents, sizeof(filemetaEvents)/sizeof(filemetaEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : File Metadata events");
                            }
                            break;
                        case 8:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, memoryEvents, sizeof(memoryEvents)/sizeof(memoryEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Memory events");
                            }
                            break;
                        case 9:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, pseudoterminalEvents, sizeof(pseudoterminalEvents)/sizeof(pseudoterminalEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : Pseudo Terminal events");
                            }
                            break;
                        case 10:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, fileproviderEvents, sizeof(fileproviderEvents)/sizeof(fileproviderEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : File Provider events");
                            }
                            break;
                        case 11:
                            if(ES_RETURN_SUCCESS != es_subscribe(endpointClient, systemtimeEvents, sizeof(systemtimeEvents)/sizeof(systemtimeEvents[0])))
                            {
                                NSLog(@"ERROR: es_subscribe() failed");
                                goto bail;
                            } else {
                                NSLog(@"Subscribed to event group : System Time events");
                            }
                            break;
                        default:
                            NSLog(@"Tried to subscribe to unknown event group, terminating!");
                            exit(1);
                            
                    }
                    
                }
                
            } else {
                
            }
        }
    }
    
    started = YES;
    
bail:
    return started;
}

-(BOOL)stop
{
     //flag
    BOOL stopped = NO;
    
    //sync
    @synchronized (self)
    {
        
        //unsubscribe & delete
        if(NULL != endpointClient)
        {
           //unsubscribe
            if(ES_RETURN_SUCCESS != es_unsubscribe_all(endpointClient))
            {
                //err msg
                NSLog(@"ERROR: es_unsubscribe_all() failed");
                
                //bail
                goto bail;
            }
           
           //delete client
            if(ES_RETURN_SUCCESS != es_delete_client(endpointClient))
            {
                //err msg
                NSLog(@"ERROR: es_delete_client() failed");
                
                //bail
                goto bail;
            }
           
           //unset
           endpointClient = NULL;
           
           //happy
           stopped = YES;
        }
        
    } //sync
    
bail:
    
    return stopped;
}

@end


// Primary class definiition
@implementation SecurityEvent

-(id)init:(es_message_t*)message
{
    // Creates instance of SecurityEvent object as "self" which has fields as determined in header file.
    self = [super init];
    if (nil != self)
        {
            // We don't care about messages for the es_client binary
            if (!message->process->is_es_client) {
                
                self.timestamp = [NSDate date];
                self.hostname = [[NSHost currentHost] name];
                self.metadata = [NSMutableDictionary dictionary];
                // Send the event type to a switch statement to determine STRING return for logging
                self.type = event_type_str(message->event_type);
                
                [self extractOriginProcessDataForEvent:message->process];
            
                
                // Handle the event and extract the event details as metadata
                switch (message->event_type) {
                       
                    case ES_EVENT_TYPE_NOTIFY_EXEC:
                        // extract the arguments for exec events
                        self.eventGroup = @"process";
                        [self extractArgs:&message->event];
                        [self handleProcessEventData:message->event.exec.target];
                        [self extractEnvironmentVariablesForProcess:&message->event.exec];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_FORK:
                        self.eventGroup = @"process";
                        [self handleProcessEventData:message->event.fork.child];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_EXIT:
                        self.eventGroup = @"process";
                        [self handleProcessEventData:message->process];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_CHDIR:
                        self.eventGroup = @"process";
                        //[self handleProcessEventData:message->process];
                        [self handleProcessChangeDirEventData:&message->event.chdir];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_CHROOT:
                        self.eventGroup = @"process";
                        [self handleProcessChangeRootEventDagta:&message->event.chroot];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_SIGNAL:
                        self.eventGroup = @"process";
                        //[self handleProcessEventData:message->process];
                        [self handleProcessSignalEventData:&message->event.signal];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
                        self.eventGroup = @"process";
                        [self handleProcessInformationRequestEventData:&message->event.proc_check];
                        if(message->event.proc_check.target != NULL)
                        {
                            [self handleProcessEventData:message->event.proc_check.target];
                        }
                        break;
                    case ES_EVENT_TYPE_NOTIFY_GET_TASK:
                        self.eventGroup = @"process";
                        [self handleGetTaskEventData:&message->event.get_task];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_CREATE:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_DUP:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_OPEN:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_WRITE:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_CLOSE:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_CLONE:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
                        self.eventGroup = @"file";
                        [self handleFileTruncationEventData:&message->event.truncate];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_LOOKUP:
                        self.eventGroup = @"file";
                        [self handleFileLookupEventData:&message->event.lookup];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_FCNTL:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_ACCESS:
                        self.eventGroup = @"file";
                        [self handleFileAccessCheckEventDatya:&message->event.access];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_LINK:
                        self.eventGroup = @"symLink";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_UNLINK:
                        self.eventGroup = @"symLink";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_READLINK:
                        self.eventGroup = @"symLink";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_RENAME:
                        self.eventGroup = @"file";
                        [self extractPaths:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
                        self.eventGroup = @"file";
                        [self handleFileDataExchange:&message->event.exchangedata];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
                        self.eventGroup = @"socket";
                        [self handleBindingSocketEventData:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                        self.eventGroup = @"socket";
                        [self handleConnectingSocketEventData:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
                        self.eventGroup = @"kernelExtension";
                        [self handleKextEventData:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
                        self.eventGroup = @"kernelExtension";
                        [self handleKextEventData:message];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
                        self.eventGroup = @"kernelExtension";
                        [self.metadata setValue:convertStringToken(&message->event.iokit_open.user_client_class) forKey:@"user_class"];
                        [self.metadata setValue:[NSNumber numberWithUnsignedInt:message->event.iokit_open.user_client_type] forKey:@"user_client"];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
                        self.eventGroup = @"fileMetadata";
                        [self handleSetAttrlistEventData:&message->event.setattrlist];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
                        self.eventGroup = @"fileMetadata";
                        [self handleGetAttrlistEventData:&message->event.getattrlist];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
                        self.eventGroup = @"fileMetadata";
                        [self handleGetExtendedAttributeEventData:&message->event.getextattr];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
                        self.eventGroup = @"fileMetadata";
                        [self handleListExtendedAttributes:&message->event.listextattr];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
                        self.eventGroup = @"fileMetadata";
                        [self handleDeleteExtendedAttributeEventData:&message->event.deleteextattr];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
                        self.eventGroup = @"fileMetadata";
                        [self handleSetExtattrEventData:&message->event.setextattr];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_SETOWNER:
                        self.eventGroup = @"fileMetadata";
                        [self handleSetOwnerEventData:&message->event.setowner];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
                        self.eventGroup = @"fileMetadata";
                        [self handleSetFlagsEventData:&message->event.setflags];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_SETMODE:
                        self.eventGroup = @"fileMetadata";
                        [self handleSetModeEventData:&message->event.setmode];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_SETACL:
                        self.eventGroup = @"fileMetadata";
                        [self handleSetFileAclEventData:&message->event.setacl];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_UTIMES:
                        self.eventGroup = @"fileMetadata";
                        [self handleUpdateTimesEventDAta:&message->event.utimes];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_READDIR:
                        self.eventGroup = @"fileMetadata";
                        [self handleReadDirectoryEventData:&message->event.readdir];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
                        self.eventGroup = @"fileMetadata";
                        [self handleFileSystemGetPathEventData:&message->event.fsgetpath];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_STAT:
                        self.eventGroup = @"fileMetadata";
                        [self handleGetFileStatusEventData:&message->event.stat];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_MMAP:
                        self.eventGroup = @"memory";
                        [self handleMMapEventData:&message->event.mmap];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_MPROTECT:
                        self.eventGroup = @"memory";
                        [self handleMprotectEventData:&message->event.mprotect];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
                        self.eventGroup = @"pseudoTerminal";
                        [self handlePsuedoterminalClosureEvent:&message->event.pty_close];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
                        self.eventGroup = @"pseudoTerminal";
                        [self handlePsuedoterminalGrantEvent:&message->event.pty_grant];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_MOUNT:
                        self.eventGroup = @"fileSystemMount";
                        [self handleDeviceMountEventData:&message->event.mount];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
                        self.eventGroup = @"fileSystemMount";
                        [self handleDeviceUnmountEventData:&message->event.unmount];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
                        self.eventGroup = @"fileProvider";
                        [self handleProcessEventData:message->event.file_provider_materialize.instigator];
                        [self handleFileProviderMaterializeEventData:&message->event.file_provider_materialize];
                        break;
                    case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
                        self.eventGroup = @"fileProvider";
                        [self handleFileProviderUpdateEventData:&message->event.file_provider_update];
                    case ES_EVENT_TYPE_NOTIFY_SETTIME:
                        self.eventGroup = @"systemTime";
                        [self handleProcessEventData:message->process];
                        break;
                    case ES_EVENT_TYPE_LAST:
                        break; // Don't care
                    default:
                        break;
                }
                return self;
            }
            return nil;
        }
    return nil;
}

-(void)handleProcessInformationRequestEventData:(es_event_proc_check_t *)procCheck
{
    if(procCheck->type == ES_PROC_CHECK_TYPE_DIRTYCONTROL)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_DIRTYCONTROL" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_KERNMSGBUF)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_KERNMSGBUF" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_LISTPIDS)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_LISTPIDS" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_PIDFDINFO)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_PIDFDINFO" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_PIDFILEPORTINFO)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_PIDFILEPORTINFO" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_PIDINFO)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_PIDINFO" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_PIDRUSAGE)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_PIDRUSAGE" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_SETCONTROL)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_SETCONTROL" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_TERMINATE)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_TERMINATE" forKey:@"type"];
    } else if (procCheck->type == ES_PROC_CHECK_TYPE_UDATA_INFO)
    {
        [self.metadata setValue:@"ES_PROC_CHECK_TYPE_UDATA_INFO" forKey:@"type"];
    }
    [self.metadata setValue:[NSNumber numberWithInt:procCheck->flavor] forKey:@"flavor"];
}

-(void)handleSetFileAclEventData:(es_event_setacl_t *)setAcl
{
    [self.metadata setValue:convertStringToken(&setAcl->target->path) forKey:@"target_file"];
    if(setAcl->set_or_clear == ES_SET){
        [self.metadata setValue:@"ES_SET" forKey:@"set_or_clear"];
        // TODO - there is a bug issue here due to bad memory access. ASSESS
        [self.metadata setValue:[NSString stringWithCString:acl_to_text(setAcl->acl.set, NULL) encoding:NSASCIIStringEncoding] forKey:@"acl_value"];
    } else {
        [self.metadata setValue:@"ES_CLEAR" forKey:@"set_or_clear"];
    }
}

-(void)handleDeleteExtendedAttributeEventData:(es_event_deleteextattr_t *)deleteExt
{
    [self.metadata setValue:convertStringToken(&deleteExt->target->path) forKey:@"target_file"];
    [self.metadata setValue:convertStringToken(&deleteExt->extattr) forKey:@"extended_attrbiute"];
}

-(void)handleListExtendedAttributes:(es_event_listextattr_t *)listExt
{
    [self.metadata setValue:convertStringToken(&listExt->target->path) forKey:@"target_file"];
}

-(void)handleGetExtendedAttributeEventData:(es_event_getextattr_t *)getExt
{
    [self.metadata setValue:convertStringToken(&getExt->target->path) forKey:@"target_file"];
    [self.metadata setValue:convertStringToken(&getExt->extattr) forKey:@"extended_attrbiute"];
}

-(void)handleGetFileStatusEventData:(es_event_stat_t *)stat
{
    [self.metadata setValue:convertStringToken(&stat->target->path) forKey:@"target_file"];
}

-(void)handleFileSystemGetPathEventData:(es_event_fsgetpath_t *)fsgetpath
{
    [self.metadata setValue:convertStringToken(&fsgetpath->target->path) forKey:@"target_file"];
}

-(void)handleReadDirectoryEventData:(es_event_readdir_t *)readdir
{
    [self.metadata setValue:convertStringToken(&readdir->target->path) forKey:@"target_file"];
}

-(void)handleUpdateTimesEventDAta:(es_event_utimes_t *)utime
{
    [self.metadata setValue:convertStringToken(&utime->target->path) forKey:@"target_file"];
    [self.metadata setValue:[NSNumber numberWithLong:utime->atime.tv_sec] forKey:@"new_last_accessed_time"];
    [self.metadata setValue:[NSNumber numberWithLong:utime->mtime.tv_sec] forKey:@"new_last_modified_time"];
}

-(void)handleProcessChangeRootEventDagta:(es_event_chroot_t *)chroot
{
    [self.metadata setValue:convertStringToken(&chroot->target->path) forKey:@"new_root_dir"];
}

-(void)handleFileAccessCheckEventDatya:(es_event_access_t *)access
{
    [self.metadata setValue:convertStringToken(&access->target->path) forKey:@"target_file"];
    [self.metadata setValue:[NSNumber numberWithInt:access->mode] forKey:@"file_mode_checked"];
}

-(void)handleFileLookupEventData:(es_event_lookup_t *)lookup
{
    [self.metadata setValue:convertStringToken(&lookup->source_dir->path) forKey:@"source_dir"];
    [self.metadata setValue:convertStringToken(&lookup->relative_target) forKey:@"realtive_target"];
}

-(void)handleFileTruncationEventData:(es_event_truncate_t *)truncation
{
    [self.metadata setValue:convertStringToken(&truncation->target->path) forKey:@"target_file"];
}

-(void)handleFileProviderUpdateEventData:(es_event_file_provider_update_t *)fileProviderU
{
    [self.metadata setValue:convertStringToken(&fileProviderU->source->path) forKey:@"sourceFile"];
    [self.metadata setValue:convertStringToken(&fileProviderU->target_path) forKey:@"targetPath"];
}

-(void)handleFileProviderMaterializeEventData:(es_event_file_provider_materialize_t *)fileProviderM
{
    [self.metadata setValue:convertStringToken(&fileProviderM->source->path) forKey:@"sourceFile"];
    [self.metadata setValue:convertStringToken(&fileProviderM->target->path) forKey:@"targetFile"];
}

-(void)handleProcessSignalEventData:(es_event_signal_t *)signalSent
{
    [self.metadata setValue:[NSNumber numberWithInt:signalSent->sig] forKey:@"signalSent"];
    [self handleProcessEventData:signalSent->target];
}

-(void)handleSetModeEventData:(es_event_setmode_t *)modeSet
{
    [self.metadata setValue:convertStringToken(&modeSet->target->path) forKey:@"filePath"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:modeSet->mode] forKey:@"mode"];
}

-(void)handleProcessChangeDirEventData:(es_event_chdir_t *)changeDir
{
    [self.metadata setValue:convertStringToken(&changeDir->target->path) forKey:@"newDirectory"];
}

-(void)handleSetFlagsEventData:(es_event_setflags_t *)setFlags
{
    [self.metadata setValue:convertStringToken(&setFlags->target->path) forKey:@"filePath"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:setFlags->flags] forKey:@"rawSetFlags"];
}

-(void)handleMprotectEventData:(es_event_mprotect_t *)mProtect
{
    [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:mProtect->address] forKey:@"startAddress"];
    [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:mProtect->size] forKey:@"size"];
    [self.metadata setValue:[NSNumber numberWithInt:mProtect->protection] forKey:@"protectionSet"];
}

-(void)handleDeviceMountEventData:(es_event_mount_t *)deviceMount
{
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:deviceMount->statfs->f_owner] forKey:@"device_user_id"];
    //[self.metadata setValue:[NSString stringWithCharacters:deviceMount->statfs->f_mntfromname length:90] forKey:@"device_mount_from"];
    [self.metadata setValue:[NSString stringWithCString:deviceMount->statfs->f_mntfromname encoding:NSASCIIStringEncoding] forKey:@"device_mount_from"];
    [self.metadata setValue:[NSString stringWithCString:deviceMount->statfs->f_mntonname encoding:NSASCIIStringEncoding] forKey:@"device_mount_to"];
    [self.metadata setValue:[NSNumber numberWithInt:deviceMount->statfs->f_fsid.val[1]] forKey:@"file_system_id"];
}

-(void)handleDeviceUnmountEventData:(es_event_unmount_t *)deviceMount
{
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:deviceMount->statfs->f_owner] forKey:@"device_user_id"];
    //[self.metadata setValue:[NSString stringWithCharacters:deviceMount->statfs->f_mntfromname length:90] forKey:@"device_mount_from"];
    [self.metadata setValue:[NSString stringWithCString:deviceMount->statfs->f_mntfromname encoding:NSASCIIStringEncoding] forKey:@"device_unmount_from"];
    [self.metadata setValue:[NSString stringWithCString:deviceMount->statfs->f_mntonname encoding:NSASCIIStringEncoding] forKey:@"device_unmount_to"];
    [self.metadata setValue:[NSNumber numberWithInt:deviceMount->statfs->f_fsid.val[1]] forKey:@"file_system_id"];
}

-(void)handleFileDataExchange:(es_event_exchangedata_t *)fileExchange
{
    [self.metadata setValue:convertStringToken(&fileExchange->file1->path) forKey:@"file_1_path"];
    [self.metadata setValue:[NSNumber numberWithBool:fileExchange->file1->path_truncated] forKey:@"file_1_path_truncated"];
    [self.metadata setValue:convertStringToken(&fileExchange->file2->path) forKey:@"file_2_path"];
    [self.metadata setValue:[NSNumber numberWithBool:fileExchange->file2->path_truncated] forKey:@"file_2_path_truncated"];
}

-(void)handleGetTaskEventData:(es_event_get_task_t *)task
{
    //obtain all the target process info. Just re-use the handleProcessEvent function
    [self handleProcessEventData:task->target];
}

-(void)handleSetOwnerEventData:(es_event_setowner_t *)owner
{
    [self.metadata setValue:convertStringToken(&owner->target->path) forKey:@"filepath"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:owner->uid] forKey:@"uid"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:owner->gid] forKey:@"gid"];
}

-(void)handleSetExtattrEventData:(es_event_setextattr_t *)extattr
{
    [self.metadata setValue:convertStringToken(&extattr->target->path) forKey:@"filepath"];
    [self.metadata setValue:convertStringToken(&extattr->extattr) forKey:@"extendedattr"];
}

-(void)handleGetAttrlistEventData:(es_event_getattrlist_t *)attr
{
    [self.metadata setValue:convertStringToken(&attr->target->path) forKey:@"filepath"];
    // TODO
    // Attributes list could do with some polishing to make it more readable rather than raw int values
    struct attrlist list = attr->attrlist;
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.commonattr] forKey:@"commonattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.volattr] forKey:@"volattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.dirattr] forKey:@"dirattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.fileattr] forKey:@"fileattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.forkattr] forKey:@"forkattr"];
}

-(void)handleSetAttrlistEventData:(es_event_setattrlist_t *)attr
{
    [self.metadata setValue:convertStringToken(&attr->target->path) forKey:@"filepath"];
    // TODO
    // Attributes list could do with some polishing to make it more readable rather than raw int values
    struct attrlist list = attr->attrlist;
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.commonattr] forKey:@"commonattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.volattr] forKey:@"volattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.dirattr] forKey:@"dirattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.fileattr] forKey:@"fileattr"];
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:list.forkattr] forKey:@"forkattr"];
}

-(void)extractOriginProcessDataForEvent:(es_process_t *)process
{
    NSString *binarypath = convertStringToken(&process->executable->path);
    NSNumber *pid = [NSNumber numberWithInt:audit_token_to_pid(process->audit_token)];
    NSNumber *uid = [NSNumber numberWithInt:audit_token_to_euid(process->audit_token)];
    NSNumber *ppid = [NSNumber numberWithInt:process->ppid];
    pid_t process_pid = audit_token_to_pid(process->audit_token);
    
    [self.metadata setValue:binarypath forKey:@"origin_binarypath"];
    [self.metadata setValue:pid forKey:@"origin_pid"];
    [self.metadata setValue:uid forKey:@"origin_uid"];
    [self.metadata setValue:ppid forKey:@"origin_ppid"];
    [self.metadata setValue:[NSNumber numberWithInt:getRealParentProcessId(process_pid)] forKey:@"origin_real_ppid"];
    [self extractSigningInfo:process forOriginProcess:true];
}

-(void)handlePsuedoterminalGrantEvent:(es_event_pty_grant_t *)psuedoTerm
{
    [self.metadata setValue:[NSNumber numberWithInt:major(psuedoTerm->dev)] forKey:@"device_major_value"];
    [self.metadata setValue:[NSNumber numberWithInt:minor(psuedoTerm->dev)] forKey:@"device_minor_value"];
}

-(void)handlePsuedoterminalClosureEvent:(es_event_pty_close_t *)psuedoTerm
{
    [self.metadata setValue:[NSNumber numberWithInt:major(psuedoTerm->dev)] forKey:@"device_major_value"];
    [self.metadata setValue:[NSNumber numberWithInt:minor(psuedoTerm->dev)] forKey:@"device_minor_value"];
}

-(void)handleKextEventData:(es_message_t *)kext
{
    NSString *kextID;
    switch (kext->event_type) {
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            kextID = convertStringToken(&kext->event.kextload.identifier);
            break;
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            kextID = convertStringToken(&kext->event.kextunload.identifier);
        default:
            break;
    }
    
    NSURL *url = CFBridgingRelease(KextManagerCreateURLForBundleIdentifier(kCFAllocatorDefault, (__bridge CFStringRef)kextID));
    
    if (url) {
        NSBundle *bundle = [NSBundle bundleWithURL:url];
        [self.metadata setValue:bundle.bundleIdentifier forKey:@"bundleidentifier"];
        [self.metadata setValue:bundle.bundlePath forKey:@"bundlepath"];
        [self.metadata setValue:bundle.executablePath forKey:@"executable"];
        
        // TODO:
    } else {
        // If the path is null
        // TODO: KextManagerCreateURLForBundleIdentifier function supposedly only works for kexts that are located in /System/Library/KernelExtensions/. Need logic to handle third-party kexts
    }
}

-(void)handleMMapEventData:(es_event_mmap_t *)mmap
{
    // obtain properties for the source es_file_t struct
    [self.metadata setValue:convertStringToken(&mmap->source->path) forKey:@"sourcepath"];
    [self.metadata setValue:[NSNumber numberWithBool:mmap->source->path_truncated] forKey:@"path_truncated"];
    
    // obtain some of the other mmap properties
    [self.metadata setValue:[NSNumber numberWithUnsignedLong:mmap->file_pos] forKey:@"fileoffset"];
    @try {
        //Obtain the MMAP flags
        NSMutableArray *mmapflags = [[NSMutableArray alloc] init];
        [self.metadata setValue:mmapflags forKey:@"mmapflags"];
        
        if ((MAP_SHARED & mmap->flags) == MAP_SHARED) {
            [self.metadata[@"mmapflags"] addObject:@"MAP_SHARED"];
        }
        
        if ((MAP_PRIVATE & mmap->flags) == MAP_PRIVATE) {
            [self.metadata[@"mmapflags"] addObject:@"MAP_PRIVATE"];
        }
        
        if ((MAP_FIXED & mmap->flags) == MAP_FIXED) {
            [self.metadata[@"mmapflags"] addObject:@"MAP_FIXED"];
        }
        
        //Obtain the MMAP protection values
        NSMutableArray *mmapprotection = [[NSMutableArray alloc] init];
        [self.metadata setValue:mmapprotection forKey:@"mmapprotection"];
        
        if ((PROT_EXEC & mmap->protection) == PROT_EXEC) {
            [self.metadata[@"mmapprotection"] addObject:@"PROT_EXEC"];
        }
        
        if ((PROT_WRITE & mmap->protection) == PROT_WRITE) {
            [self.metadata[@"mmapprotection"] addObject:@"PROT_WRITE"];
        }
        
        if ((PROT_READ & mmap->protection) == PROT_READ) {
            [self.metadata[@"mmapprotection"] addObject:@"PROT_READ"];
        }
        
        if ((PROT_NONE & mmap->protection) == PROT_NONE) {
            [self.metadata[@"mmapprotection"] addObject:@"PROT_NONE"];
        }
    } @catch (NSException *exception) {
        
    }
}
//extract/format signing info Written by Patrick Wardle
-(void)extractSigningInfo:(es_process_t *)process forOriginProcess:(bool)forOriginalProcess
{
    NSString *codeSignKey;
    NSString *signingIDKey;
    NSString *teamIDKey;
    NSString *cdHashKey;
    NSString *platformBinaryKey;
    
    if (forOriginalProcess) {
        codeSignKey = @"origin_codesigningflags";
        signingIDKey = @"origin_signingid";
        teamIDKey = @"origin_teamid";
        cdHashKey = @"origin_cdhash";
        platformBinaryKey = @"origin_platform_binary";
    } else {
        codeSignKey = @"codesigningflags";
        signingIDKey = @"signingid";
        teamIDKey = @"teamid";
        cdHashKey = @"cdhash";
        platformBinaryKey = @"platform_binary";
    }
    
    //cd hash
    NSMutableString* cdHash = nil;
    
    //signing id
    NSString* signingID = nil;
    
    //team id
    NSString* teamID = nil;
    
    //alloc string for hash
    cdHash = [NSMutableString string];
    
    //add flags
    //TODO
    // Possible remove as not really seeing the significance
    [self parseCodeSignFlags:process->codesigning_flags keyName:codeSignKey];
    
    
    //convert/add signing id
    signingID = convertStringToken(&process->signing_id);
    if(nil != signingID)
    {
        //add
        [self.metadata setValue:signingID forKey:signingIDKey];
    }
    
    //convert/add team id
    teamID = convertStringToken(&process->team_id);
    if(nil != teamID)
    {
        
        [self.metadata setValue:teamID forKey:teamIDKey];
    }
    
    
    [self.metadata setValue:[NSNumber numberWithBool:process->is_platform_binary] forKey:platformBinaryKey];
    
    //format cdhash
    for(uint32_t i = 0; i<CS_CDHASH_LEN; i++)
    {
        //append
        [cdHash appendFormat:@"%X", process->cdhash[i]];
    }
    
    
    [self.metadata setValue:cdHash forKey:cdHashKey];
    
    return;
}


//TODO
// Not sure if this is necessary, possiby remove?
-(void)parseCodeSignFlags:(uint32_t)value keyName:(NSString*)keyName
{
    @try {
        NSMutableArray *keynamearray = [[NSMutableArray alloc] init];
        [self.metadata setValue:keynamearray forKey:keyName];
        
        if ((CS_ADHOC & value) == CS_ADHOC) {
            [self.metadata[keyName] addObject:@"CS_ADHOC"];
        }
        
        if ((CS_HARD & value) == CS_HARD) {
            [self.metadata[keyName] addObject:@"CS_HARD"];
        }
        
        if ((CS_KILL & value) == CS_KILL) {
            [self.metadata[keyName] addObject:@"CS_KILL"];
        }
        
        if ((CS_VALID & value) == CS_VALID) {
            [self.metadata[keyName] addObject:@"CS_VALID"];
        }
        
        if ((CS_KILLED & value) == CS_KILLED) {
            [self.metadata[keyName] addObject:@"CS_KILLED"];
        }
        
        if ((CS_SIGNED & value) == CS_SIGNED) {
            [self.metadata[keyName] addObject:@"CS_SIGNED"];
        }
        
        if ((CS_RUNTIME & value) == CS_RUNTIME) {
            [self.metadata[keyName] addObject:@"CS_RUNTIME"];
        }
        
        if ((CS_DEBUGGED & value) == CS_DEBUGGED) {
            [self.metadata[keyName] addObject:@"CS_DEBUGGED"];
        }
        
        if ((CS_DEV_CODE & value) == CS_DEV_CODE) {
            [self.metadata[keyName] addObject:@"CS_DEV_CODE"];
        }
        
        if ((CS_RESTRICT & value) == CS_RESTRICT) {
            [self.metadata[keyName] addObject:@"CS_RESTRICT"];
        }
        
        if ((CS_FORCED_LV & value) == CS_FORCED_LV) {
            [self.metadata[keyName] addObject:@"CS_FORCED_LV"];
        }
        
        if ((CS_INSTALLER & value) == CS_INSTALLER) {
            [self.metadata[keyName] addObject:@"CS_INSTALLER"];
        }
        
        if ((CS_EXECSEG_JIT & value) == CS_EXECSEG_JIT) {
            [self.metadata[keyName] addObject:@"CS_EXECSEG_JIT"];
        }
        
        if ((CS_REQUIRE_LV & value) == CS_REQUIRE_LV) {
            [self.metadata[keyName] addObject:@"CS_EXECSEG_JIT"];
        }
        
        if ((CS_ALLOWED_MACHO & value) == CS_ALLOWED_MACHO) {
            [self.metadata[keyName] addObject:@"CS_ALLOWED_MACHO"];
        }
        
        if ((CS_ENFORCEMENT & value) == CS_ENFORCEMENT) {
            [self.metadata[keyName] addObject:@"CS_ENFORCEMENT"];
        }
        
        if ((CS_DYLD_PLATFORM & value) == CS_DYLD_PLATFORM) {
            [self.metadata[keyName] addObject:@"CS_DYLD_PLATFORM"];
        }
        
        if ((CS_EXEC_SET_HARD & value) == CS_EXEC_SET_HARD) {
            [self.metadata[keyName] addObject:@"CS_EXEC_SET_HARD"];
        }
        
        if ((CS_PLATFORM_PATH & value) == CS_PLATFORM_PATH) {
            [self.metadata[keyName] addObject:@"CS_PLATFORM_PATH"];
        }
        
        if ((CS_GET_TASK_ALLOW & value) == CS_GET_TASK_ALLOW) {
            [self.metadata[keyName] addObject:@"CS_GET_TASK_ALLOW"];
        }
        
        if ((CS_EXEC_SET_KILL & value) == CS_EXEC_SET_KILL) {
            [self.metadata[keyName] addObject:@"CS_EXEC_SET_KILL"];
        }
        
        if ((CS_EXECSEG_SKIP_LV & value) == CS_EXECSEG_SKIP_LV) {
            [self.metadata[keyName] addObject:@"CS_EXECSEG_SKIP_LV"];
        }
        
        if ((CS_INVALID_ALLOWED & value) == CS_INVALID_ALLOWED) {
            [self.metadata[keyName] addObject:@"CS_INVALID_ALLOWED"];
        }
        
        if ((CS_CHECK_EXPIRATION & value) == CS_CHECK_EXPIRATION) {
            [self.metadata[keyName] addObject:@"CS_INVALID_ALLOWED"];
        }
        
        if ((CS_PLATFORM_BINARY & value) == CS_PLATFORM_BINARY) {
            [self.metadata[keyName] addObject:@"CS_PLATFORM_BINARY"];
        }
        
        if ((CS_EXEC_INHERIT_SIP & value) == CS_EXEC_INHERIT_SIP) {
            [self.metadata[keyName] addObject:@"CS_EXEC_INHERIT_SIP"];
        }
        
        if ((CS_EXECSEG_ALLOW_UNSIGNED & value) == CS_EXECSEG_ALLOW_UNSIGNED) {
            [self.metadata[keyName] addObject:@"CS_EXECSEG_ALLOW_UNSIGNED"];
        }
        
        if ((CS_EXECSEG_DEBUGGER & value) == CS_EXECSEG_DEBUGGER) {
            [self.metadata[keyName] addObject:@"CS_EXECSEG_DEBUGGER"];
        }
        
        if ((CS_ENTITLEMENT_FLAGS & value) == CS_ENTITLEMENT_FLAGS) {
            [self.metadata[keyName] addObject:@"CS_ENTITLEMENT_FLAGS"];
        }
        
        if ((CS_NVRAM_UNRESTRICTED & value) == CS_NVRAM_UNRESTRICTED) {
            [self.metadata[keyName] addObject:@"CS_NVRAM_UNRESTRICTED"];
        }
        
        if ((CS_EXECSEG_MAIN_BINARY & value) == CS_EXECSEG_MAIN_BINARY) {
            [self.metadata[keyName] addObject:@"CS_EXECSEG_MAIN_BINARY"];
        }
    } @catch (NSException *exception) {
        
    }
    
}

-(void)extractEnvironmentVariablesForProcess:(es_event_exec_t *)process
{
    @try {
        [self.metadata setValue:[NSMutableArray array] forKey:@"env_variables"];
        uint32_t count = es_exec_env_count(process);
        if (count > 0) {
            for (uint32_t i = 0; i < count; i++) {
                es_string_token_t env_value = es_exec_env(process, (uint32_t)i);
                [self.metadata[@"env_variables"] addObject:convertStringToken(&env_value)];
            }
        }
    } @catch (NSException *exception) {
        
    }
    
    
}

-(void)extractArgs:(es_events_t *)event
{
    //number of args
    uint32_t count = 0;
    
    //argument
    NSString* argument = nil;
    NSMutableArray *arguments = [[NSMutableArray alloc] init];
    
    //get # of args
    if (@available(macOS 10.15, *)) {
        count = es_exec_arg_count(&event->exec);
    } else {
        // Fallback on earlier versions
    }
    if(0 == count)
    {
        //bail
        return;
    }
    
    //extract all args
    for(uint32_t i = 0; i < count; i++)
    {
        //current arg
        es_string_token_t currentArg = {0};
        
        //extract current arg
        if (@available(macOS 10.15, *)) {
            currentArg = es_exec_arg(&event->exec, i);
        } else {
            // Fallback on earlier versions
        }
        
        //convert argument
        argument = convertStringToken(&currentArg);
        if(nil != argument)
        {
            //TODO: Add the process arguments to the metadata dictionary
            //[self.metadata setValue:argument forKey:@"ProcessArgs"];
            [arguments addObject:argument];
        }
    }
    NSString *argumentString = [[arguments valueForKey:@"description"] componentsJoinedByString:@" "];
    [self.metadata setValue:argumentString forKey:@"procCommandLine"];
    
}

-(void)extractPaths:(es_message_t*)message
{
    //event specific logic
    switch (message->event_type) {
        
        //create
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            
            //set path
            
            [self.metadata setValue:convertStringToken(&message->event.create.destination.existing_file->path) forKey:@"fileFullPath"];
            
            self.uid = [NSNumber numberWithInt:message->event.create.destination.existing_file->stat.st_uid];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.create.destination.existing_file->stat.st_size] forKey:@"filesize"];
            
            break;
            
        //duplication of descriptor
        case ES_EVENT_TYPE_NOTIFY_DUP:
            [self.metadata setValue:convertStringToken(&message->event.dup.target->path) forKey:@"fileFullPath"];
            break;
            
        //open
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            
            //set path
            [self.metadata setValue:convertStringToken(&message->event.open.file->path) forKey:@"fileFullPath"];
            break;
            
        //write
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            
            //set path
            [self.metadata setValue:convertStringToken(&message->event.write.target->path) forKey:@"fileFullPath"];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.write.target->stat.st_size] forKey:@"filesize"];
            
            self.uid = [NSNumber numberWithUnsignedLongLong:message->event.write.target->stat.st_uid];
            
            break;
            
        //close
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            
            //set path
            
            [self.metadata setValue:convertStringToken(&message->event.close.target->path) forKey:@"fileFullPath"];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.close.target->stat.st_size] forKey:@"filesize"];
            
            self.uid = [NSNumber numberWithUnsignedLongLong:message->event.close.target->stat.st_uid];
            
            
            break;
        
        //clone
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            [self.metadata setValue:convertStringToken(&message->event.clone.source->path) forKey:@"sourcefilepath"];
            [self.metadata setValue:convertStringToken(&message->event.clone.target_name) forKey:@"target_name"];
            [self.metadata setValue:convertStringToken(&message->event.clone.target_dir->path) forKey:@"target_directory"];
            break;
            
        //descriptor edit -
        // TODO - (fcntl cmd int value translation to add later?)
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            [self.metadata setValue:convertStringToken(&message->event.fcntl.target->path) forKey:@"fileFullPath"];
            [self.metadata setValue:[NSNumber numberWithInt:message->event.fcntl.cmd] forKey:@"command"];
            break;
        
        //link
        case ES_EVENT_TYPE_NOTIFY_LINK:
            
            //set (src) path
            [self.metadata setValue:convertStringToken(&message->event.link.source->path) forKey:@"sourcefilepath"];
            [self.metadata setValue:convertStringToken(&message->event.link.target_filename) forKey:@"destinationFileName"];
            
            break;
            
        //rename
        case ES_EVENT_TYPE_NOTIFY_RENAME:
                
            //set (src) path
            [self.metadata setValue:convertStringToken(&message->event.rename.source->path) forKey:@"sourcefilepath"];
            
            //existing file ('ES_DESTINATION_TYPE_EXISTING_FILE')
            if(ES_DESTINATION_TYPE_EXISTING_FILE == message->event.rename.destination_type)
            {
                //set (dest) file
                [self.metadata setValue:convertStringToken(&message->event.rename.destination.existing_file->path) forKey:@"destinationfilepath"];
            }
            else
            {
                //set (dest) path
                // combine dest dir + dest file
                [self.metadata setValue:[convertStringToken(&message->event.rename.destination.new_path.dir->path) stringByAppendingPathComponent:convertStringToken(&message->event.rename.destination.new_path.filename)] forKey:@"destinationfilepath"];
            }
            
            break;
            
        //unlink
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
                
            //set path
            [self.metadata setValue:convertStringToken(&message->event.unlink.target->path) forKey:@"fileFullPath"];
            [self.metadata setValue:[NSNumber numberWithUnsignedLongLong:message->event.unlink.target->stat.st_size] forKey:@"filesize"];
            self.uid = [NSNumber numberWithUnsignedLongLong:message->event.unlink.target->stat.st_uid];
                
            break;
            
        //read link
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            [self.metadata setValue:convertStringToken(&message->event.readlink.source->path) forKey:@"sourcePath"];
            
        default:
            break;
    }
    
    return;
}

// Helper function to convert NSDate to NSString for json serialization
-(NSString*)nsDateToString
{
    NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
    [dateFormat setDateFormat:@"yyyy'-'MM'-'dd'T'HH':'mm':'ss.SSS'Z'"];
    [dateFormat setTimeZone:[NSTimeZone timeZoneWithName:@"GMT"]];
    return [dateFormat stringFromDate:self.timestamp];
}

// handle process events in general
-(void)handleProcessEventData:(es_process_t *)process
{
    // Populate values for pid for the general event info and for the metadata
    NSString* team = nil;
    pid_t process_pid = audit_token_to_pid(process->audit_token);
    [self.metadata setValue:[NSNumber numberWithInt:audit_token_to_pid(process->audit_token)] forKey:@"procPid"];
    [self.metadata setValue:[NSNumber numberWithInt:audit_token_to_euid(process->audit_token)] forKey:@"procUid"];
    [self.metadata setValue:convertStringToken(&process->executable->path) forKey:@"procFileFullPath"];
    [self.metadata setValue:[NSNumber numberWithInt:process->ppid] forKey:@"parentProcPid"];
    [self.metadata setValue:[NSNumber numberWithInt:process->original_ppid] forKey:@"original_ppid"];
    [self.metadata setValue:[NSString stringWithString:getParentInfo(process->ppid)] forKey:@"parentProcFileFullPath"];
    [self.metadata setValue:[NSNumber numberWithInt:getRealParentProcessId(process_pid)] forKey:@"real_ppid"];
    [self.metadata setValue:[NSDictionary dictionaryWithDictionary:getSubmittedByInfo(process_pid)] forKey:@"submitted_by"];
    NSString *signingInformationFound = @"YES";
    @try {
        [self.metadata setValue:[NSString stringWithString:convertStringToken(&process->signing_id)] forKey:@"signing_id"];
    }
    @catch (NSException *exception) {
        NSString *errorProcess = [self.metadata objectForKey:@"procFileFullPath"];
        NSLog(@"Unable to obtain signing info for :%@", errorProcess);
        signingInformationFound = @"NO";
        // We'll just silently ignore the exception.
    }
    [self.metadata setValue:signingInformationFound forKey:@"signingInformationFound"];
    if (nil != (team = convertStringToken(&process->team_id))) {
      [self.metadata setValue:[NSString stringWithString:team] forKey:@"team_id"];
    }
    NSMutableString *cdHash = [NSMutableString string];
    //format cdhash
    if([signingInformationFound isEqualToString:@"YES"])
    {
        for(uint32_t i=0; i< CS_CDHASH_LEN; i++)
        {
            [cdHash appendFormat:@"%02X", process->cdhash[i]];
        }
        [self.metadata setValue:[NSMutableString stringWithString:cdHash] forKey:@"cd_hash"];
    } else {
        //Silently do nothing, cd_hash is not added
    }
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    // Make sure the file exists
    if( [fileManager fileExistsAtPath:convertStringToken(&process->executable->path) isDirectory:nil] )
    {
        NSData *data = [NSData dataWithContentsOfFile:convertStringToken(&process->executable->path)];
        unsigned char digest[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1( data.bytes, (CC_LONG)data.length, digest );
 
        NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
 
        for( int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++ )
        {
            [output appendFormat:@"%02x", digest[i]];
        }
 
        [self.metadata setValue:[NSMutableString stringWithString:output] forKey:@"sha1"];
    }
    else
    {
        unsigned char digest[CC_SHA1_DIGEST_LENGTH];
        NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
        for( int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++ )
        {
            [output appendFormat:@"%02x", digest[i]];
        }
        [self.metadata setValue:[NSMutableString stringWithString:output] forKey:@"sha1"];
    }
}

-(void)handleBindingSocketEventData:(es_message_t *)message
{
    [self.metadata setValue:convertStringToken(&message->event.uipc_bind.dir->path) forKey:@"dir"];
    [self.metadata setValue:convertStringToken(&message->event.uipc_bind.filename) forKey:@"filename"];
    // TODO
    // Translate this integer value of mode_t into permissions strings people are more familiar with
    [self.metadata setValue:[NSNumber numberWithUnsignedInt:message->event.uipc_bind.mode] forKey:@"mode"];
}

-(void)handleConnectingSocketEventData:(es_message_t *)message
{
    [self.metadata setValue:convertStringToken(&message->event.uipc_connect.file->path) forKey:@"file"];
    // Based on information from socket(2) man, and socket.h data
    [self.metadata setValue:socketDomainToString(message->event.uipc_connect.domain) forKey:@"domain"];
    // Based on information from socket(2) man, and socket.h data
    [self.metadata setValue:socketTypeToString(message->event.uipc_connect.type) forKey:@"type"];
    // Based on information in the /etc/protocol file, although this could be easily depicted from the domain
    // TODO
    // Is this required in lieue of the domain data alreeady acquired, there are 147 definitions here.
    [self.metadata setValue:[NSNumber numberWithInt:message->event.uipc_connect.protocol] forKey:@"protocol"];
}

@end

NSMutableDictionary* getConfigFromFile(NSString *filePath){
    NSMutableDictionary *results = [[NSMutableDictionary alloc] init];
    NSMutableArray *groups = [[NSMutableArray alloc] init];;
    NSMutableArray *ids = [[NSMutableArray alloc] init];;
    [results setObject:groups forKey:@"groups"];
    [results setObject:ids forKey:@"ids"];
    [results setObject:ids forKey:@"pids"];
    if (filePath == NULL){
        filePath = @"config.txt";
    }
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if([fileManager fileExistsAtPath:filePath] == YES){
        NSLog(@"Using configuration file : %@", filePath);
        //NSString *myPath = [[NSBundle mainBundle]pathForResource:filePath ofType:@"txt"];
        NSError *error;
        NSString *fileContents = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:&error];
        if (error) {
            NSLog(@"Error occurred while reading the config file, try using manual event entry in arguments. Terminating!: %@", error);
            exit(1);
        }
        NSArray *lines = [fileContents componentsSeparatedByString:@"\n"];
        for (NSString* line in lines){
            if(line.length == 0){
                continue;
            }
            else if(!([[line substringToIndex:1] isEqualToString:@"#"])){
                NSArray *lineSections = [line componentsSeparatedByString:@":"];
                if(lineSections.count == 2){
                    if([lineSections[0] isEqualToString:@"group"]){
                        [results[@"groups"] addObject:[lineSections[1] stringByReplacingOccurrencesOfString:@"\r" withString:@""]];
                    } else if([lineSections[0] isEqualToString:@"id"]){
                        [results[@"ids"] addObject:[lineSections[1] stringByReplacingOccurrencesOfString:@"\r" withString:@""]];
                    } else if([lineSections[0] isEqualToString:@"pid"]){
                        [results[@"pids"] addObject:[lineSections[1] stringByReplacingOccurrencesOfString:@"\r" withString:@""]];
                    }
                } else {
                    NSLog(@"Incorrect config file found that needs fixing for line : %@", line);
                }
            }
        }
    } else {
        NSLog(@"The config file specified does not exist! Terminating program!");
        exit(1);
    }
    return results;
}

void NSPrint (NSString *str)
{
    printf("%s\n", [str UTF8String]);
}

void NSFileLog (NSString *str, NSString *evntType, NSString *evntGroup)
{
    BOOL isDir;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error = nil;
    NSString *directory = [NSString stringWithFormat: @"%@%@", @"./", evntGroup];
    NSString *filePath = [NSString stringWithFormat:@"%@%@%@", directory, @"/", evntType];
    if (! [fileManager fileExistsAtPath:directory isDirectory:&isDir])
    {
        [fileManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:&error];
    }
    if (! [fileManager fileExistsAtPath:filePath])
    {
        [fileManager createFileAtPath:filePath contents:nil attributes:nil];
    }
    NSFileHandle* fileHandler = [NSFileHandle fileHandleForWritingAtPath:filePath];
    if (fileHandler)
    {
        NSString *output = [NSString stringWithFormat:@"%@%@", str, @"\n"];
        [fileHandler seekToEndOfFile];
        [fileHandler writeData:[output dataUsingEncoding:NSUTF8StringEncoding]];
    }
}

EventCallbackBlock _Nonnull blockStdOut = ^(SecurityEvent* newEvent)
{
    @try {
        if (nil != newEvent)
        {
            NSError *error;
            NSMutableDictionary* dataToSend = [[NSMutableDictionary alloc] init];
            [dataToSend setValue:newEvent.type forKey:@"eventtype"];
            [dataToSend setValue:[newEvent nsDateToString] forKey:@"timestamp"];
            //[dataToSend setValue:newEvent.pid forKey:@"processid"];
            [dataToSend setValue:newEvent.metadata forKey:@"metadata"];
            
            NSData* jsonData = [NSJSONSerialization dataWithJSONObject:dataToSend options:NSJSONWritingSortedKeys error:&error];
            if (! jsonData) {
                NSLog(@"Got an error: %@", error);
            }
            if(nil != jsonData)
            {
                // pretty print
                @try{
                        
                        NSError *writeError;
                        id jsonObject = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&error];
                        if(!jsonObject){
                            NSLog(@"Error occured during serialisation of json data : %@", error);
                        }
                        NSData *prettyJsonData = [NSJSONSerialization dataWithJSONObject:jsonObject options:NSJSONWritingPrettyPrinted error:&writeError];
                        if(!prettyJsonData){
                            NSLog(@"Error occured during pretificaiton of json data : %@", writeError);
                        }
                        //NSString *jsonString = [NSString stringWithUTF8String:[prettyJsonData bytes]];
                        NSString *jsonString = [[NSString alloc] initWithData:prettyJsonData encoding:NSUTF8StringEncoding];
                           if(nil == jsonString || writeError != nil){
                                NSLog(@"Json filtering failed and was null");
                        }
                    NSFileLog(jsonString, newEvent.type, newEvent.eventGroup);
                }
                @catch(NSException *exception) {
                    NSLog(@"Error during json tailoring: %@", exception);
                }
            }
        }
    } @catch (NSException *e) {
        printf("test");
    }
    
    
};

int main(int argc, const char * argv[]) {
    
    if( argc == 3 ) {
        NSString *option = [NSString stringWithUTF8String:argv[1]];
        if([option isEqualToString:@"-id"])
        {
            NSNumber *argumentType = [NSNumber numberWithInt:1];
            NSArray *types = NULL;
            NSArray *userGeneratedTypes = NULL;
            NSMutableArray *filteredTypes = [[NSMutableArray alloc] init];
            NSLog(@"Specific types provided");
            NSString *fullList = [NSString stringWithUTF8String:argv[2]];
            types = [fullList componentsSeparatedByString:@","];
            for(NSString *tempObject in types){
                NSNumber *tempId = @([tempObject intValue]);
                [filteredTypes addObject:tempId];
            }
            userGeneratedTypes = [filteredTypes copy];
            @autoreleasepool {
                Inspecter* eventMonitor = [[Inspecter alloc] init];
                NSLog(@"Capturing events...");
                [eventMonitor start:blockStdOut :userGeneratedTypes :argumentType];
                [[NSRunLoop currentRunLoop] run];
            }
        } else if ([option isEqualToString:@"-group"])
        {
            NSNumber *argumentType = [NSNumber numberWithInt:2];
            NSArray *types = NULL;
            NSArray *userGeneratedTypes = NULL;
            NSMutableArray *filteredTypes = [[NSMutableArray alloc] init];
            NSLog(@"Specific types provided");
            NSString *fullList = [NSString stringWithUTF8String:argv[2]];
            types = [fullList componentsSeparatedByString:@","];
            for(NSString *tempObject in types){
                [filteredTypes addObject:tempObject];
            }
            userGeneratedTypes = [filteredTypes copy];
            @autoreleasepool {
                Inspecter* eventMonitor = [[Inspecter alloc] init];
                NSLog(@"Capturing events...");
                [eventMonitor start:blockStdOut :userGeneratedTypes :argumentType];
                [[NSRunLoop currentRunLoop] run];
            }
        } else if ([option isEqualToString:@"-config"])
        {
            NSLog(@"Config file specified");
            NSString *filePath = [NSString stringWithUTF8String:argv[2]];
            NSMutableDictionary *config = getConfigFromFile(filePath);
            NSNumber *argumentType = [NSNumber numberWithInt:3];
            NSArray *userGeneratedTypes = NULL;
            NSMutableArray *filteredTypes = [[NSMutableArray alloc] init];
            [filteredTypes addObject:config];
            userGeneratedTypes = [filteredTypes copy];
            @autoreleasepool {
                Inspecter* eventMonitor = [[Inspecter alloc] init];
                NSLog(@"Capturing events...");
                [eventMonitor start:blockStdOut :userGeneratedTypes :argumentType];
                [[NSRunLoop currentRunLoop] run];
            }
        } else {
            NSLog(@"Incorrect option provided, closing.");
            exit(1);
        }
    } else if (argc == 1) {
        NSLog(@"ESF_Collectory by cmorley\n\n See README for full information.");
        exit(1);
    }
    else if( argc > 2 ) {
        NSLog(@"Too many arguments supplied.\n");
    } else {
        NSLog(@"Incorrect arguments.\n");
        exit(1);
}

    return 0;
}
