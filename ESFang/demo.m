//
//  main.m
//  EndpointSecurityDemo
//
//  Created by Omar Ikram on 17/06/2019 - Catalina 10.15 Beta 1 (19A471t)
//  Updated by Omar Ikram on 15/08/2019 - Catalina 10.15 Beta 5 (19A526h)
//  Updated by Omar Ikram on 01/12/2019 - Catalina 10.15 (19A583)
//

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <bsm/libbsm.h>
#import <signal.h>
#import <mach/mach_time.h>

/*
 A demo of using Apple's new EndpointSecurity framework - tested on macOS Catalina 10.15 (19A583).
 
 This demo is an update of previous demos for Catalina 10.15 Beta releases, which has been updated to
 support the final API changes Apple has made for Catalina 10.15.
 
 Disclaimer:
 This code is provided as is and is only intended to be used for illustration purposes. This code is
 not production-ready and is not meant to be used in a production environment. Use it at your own risk!
 
 Setup:
 1. Build on Xcode 11, with macOS deployment target set to 10.15.
 2. Codesign with entitlement 'com.apple.developer.endpoint-security.client'.
 
 Runtime:
 1. Test environment should be a macOS 10.15 machine which has SIP disabled (best to use a VM).
 2. Run the demo binary in a terminal as root (e.g. with sudo).
    i)  Running with no aguments will process messages serially.
    ii) Running with any arguments will delay the blocking of a matched application for 20 seconds,
        but allow other messages to be processed without being delayed.
 3. Terminal will display messages related to subscribed events.
 4. The demo will block the top binary and Calculator app bundle from running.
 5. CTL-C to exit.
 */

#pragma mark - Logging

#define BOOL_VALUE(x) x ? "Yes" : "No"
#define LOG_INFO(fmt, ...) NSLog(@#fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) NSLog(@"ERROR: " @#fmt, ##__VA_ARGS__)

NSString* esstring_to_nsstring(const es_string_token_t *es_string_token) {
    NSString *res = @"";
    
    if (es_string_token && es_string_token->data && es_string_token->length > 0) {
        // es_string_token->data is a pointer to a null-terminated string
        res = [NSString stringWithUTF8String:es_string_token->data];
    }
    
    return res;
}

NSString* event_type_str(const es_event_type_t event_type) {
    // This can be expanded to include the other ES_EVENT_TYPE_* constants
    switch(event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC: return @"ES_EVENT_TYPE_AUTH_EXEC";
        case ES_EVENT_TYPE_NOTIFY_FORK: return @"ES_EVENT_TYPE_NOTIFY_FORK";
        default: return [NSString stringWithFormat:@"Unknown/Unsupported event type: %d", event_type];
    }
}

void log_proc(const NSString* header, const es_process_t *proc) {
    if(!proc) {
        LOG_INFO("%@: (null)", header);
        return;
    }
    
    LOG_INFO("%@:", header);
    LOG_INFO("  proc.pid: %d", audit_token_to_pid(proc->audit_token));
    LOG_INFO("  proc.ppid: %d", proc->ppid);
    LOG_INFO("  proc.original_ppid: %d", proc->original_ppid);
    LOG_INFO("  proc.ruid: %d", audit_token_to_ruid(proc->audit_token));
    LOG_INFO("  proc.euid: %d", audit_token_to_euid(proc->audit_token));
    LOG_INFO("  proc.rgid: %d", audit_token_to_rgid(proc->audit_token));
    LOG_INFO("  proc.egid: %d", audit_token_to_egid(proc->audit_token));
    LOG_INFO("  proc.group_id: %d", proc->group_id);
    LOG_INFO("  proc.session_id: %d", proc->session_id);
    LOG_INFO("  proc.codesigning_flags: %x", proc->codesigning_flags);
    LOG_INFO("  proc.is_platform_binary: %s", BOOL_VALUE(proc->is_platform_binary));
    LOG_INFO("  proc.is_es_client: %s", BOOL_VALUE(proc->is_es_client));
    LOG_INFO("  proc.signing_id: %@", esstring_to_nsstring(&proc->signing_id));
    LOG_INFO("  proc.team_id: %@", esstring_to_nsstring(&proc->team_id));
    
    // proc.cdhash
    NSMutableString *hash = [NSMutableString string];
    for(uint32_t i = 0; i < CS_CDHASH_LEN; i++) {
        [hash appendFormat:@"%x", proc->cdhash[i]];
    }
    LOG_INFO("  proc.cdhash: %@", hash);
    LOG_INFO("  proc.executable.path: %@",
             proc->executable ? esstring_to_nsstring(&proc->executable->path) : @"(null)");
}

void log_event_message(const es_message_t *msg) {
    LOG_INFO("--- EVENT MESSAGE ----");
    LOG_INFO("event_type: %@ (%d)", event_type_str(msg->event_type), msg->event_type);
    // Note: Message structure could change in future versions
    LOG_INFO("version: %u", msg->version);
    LOG_INFO("time: %lld.%.9ld", (long long) msg->time.tv_sec, msg->time.tv_nsec);
    LOG_INFO("mach_time: %lld", (long long) msg->mach_time);
   
    // It's very important that the message is processed within the deadline:
    // https://developer.apple.com/documentation/endpointsecurity/es_message_t/3334985-deadline
    LOG_INFO("deadline: %lld", (long long) msg->deadline);
    
    uint64_t deadlineInterval = msg->deadline;
    
    if(deadlineInterval > 0) {
        deadlineInterval -= msg->mach_time;
    }
    
    LOG_INFO("deadline interval: %lld (%d seconds)", (long long) deadlineInterval,
             (int) (deadlineInterval / 1.0e9));
    
    LOG_INFO("action_type: %s", (msg->action_type == ES_ACTION_TYPE_AUTH) ? "Auth" : "Notify");
    log_proc(@"process", msg->process);
    
    // Type specific logging
    switch(msg->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC: {
            log_proc(@"event.exec.target", msg->event.exec.target);
            
            // Log program arguments
            uint32_t argCount = es_exec_arg_count(&msg->event.exec);
            LOG_INFO("event.exec.arg_count: %u", argCount);
            
            // Extract each argument and log it out
            for(uint32_t i = 0; i < argCount; i++) {
                es_string_token_t arg = es_exec_arg(&msg->event.exec, i);
                LOG_INFO("arg %d: %@", i, esstring_to_nsstring(&arg));
            }
        }
            break;
        
        case ES_EVENT_TYPE_NOTIFY_FORK: {
            log_proc(@"event.fork.child", msg->event.fork.child);
        }
            break;
            
        case ES_EVENT_TYPE_LAST:
        default: {
            // Not interested
        }
    }
    
    LOG_INFO("");
}

#pragma mark - Endpoint Secuirty Demo

es_client_t *g_client = nil;
NSSet *g_blockedPaths = nil;

// Clean-up before exiting
void sig_handler(int sig) {
    LOG_INFO("Tidying Up");
    
    if(g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
    }
    
    LOG_INFO("Exiting");
    exit(EXIT_SUCCESS);
}

// Simple handler to make AUTH (allow or block) decisions.
// Returns either an ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY.
es_auth_result_t auth_event_handler(const es_message_t *msg) {
    if(ES_EVENT_TYPE_AUTH_EXEC == msg->event_type) {
        NSString *path = esstring_to_nsstring(&msg->event.exec.target->executable->path);
        
        // Block if path is in our blocked paths list
        if([g_blockedPaths containsObject:path]) {
            LOG_INFO("BLOCKING: %@", path);
            return ES_AUTH_RESULT_DENY;
        }
    }
    
    return ES_AUTH_RESULT_ALLOW;
}

int main(int argc, const char * argv[]) {
    signal(SIGINT, &sig_handler);
    
    @autoreleasepool {
        // List of paths to be blocked.
        // For this demo we will block the top binary and Calculator app bundle.
        /*
        g_blockedPaths = [NSSet setWithObjects:
                          @"/usr/bin/top",
                          @"/System/Applications/Calculator.app/Contents/MacOS/Calculator",
                          nil];
        */
        // Example of a simple handler to process event messages serially from Endpoint Security
        es_handler_block_t serialHandler = ^(es_client_t *clt, const es_message_t *msg) {
                //log_event_message(msg);
                printf(msg);
                // Handle subscribed AUTH events:
                // For 'ES_EVENT_TYPE_AUTH_EXEC' events, the associated app will block until
                // an es_auth_result_t response is sent or this app exits.
                
            
                if(ES_ACTION_TYPE_AUTH == msg->action_type) {
                    es_respond_result_t res =
                        es_respond_auth_result(clt,
                                               msg,
                                               auth_event_handler(msg),
                                               false
                                               );
                    
                if(ES_RESPOND_RESULT_SUCCESS != res) {
                    LOG_ERROR("es_respond_auth_result: %d", res);
            
                }
            
            }
             
        };
        
        
        // Example of a handler to process event messages out of order from Endpoint Security.
        es_handler_block_t deferedHandler = ^(es_client_t *clt, const es_message_t *msg) {
            es_message_t *copiedMsg = es_copy_message(msg);
            
            if(!copiedMsg) {
                LOG_ERROR("Failed to copy message");
                return;
            }
            
            log_event_message(copiedMsg);
            
            // Process 'ES_ACTION_TYPE_AUTH' events on a separate thread
            // and sleep for 20s if action is ES_AUTH_RESULT_DENY.
            // Other events will not have to wait and can will be processed out of order.
            if(ES_ACTION_TYPE_AUTH == copiedMsg->action_type) {
                dispatch_async(
                    dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^(void){
                        es_auth_result_t authResult = auth_event_handler(copiedMsg);
                        
                        if(ES_AUTH_RESULT_DENY == authResult) {
                            [NSThread sleepForTimeInterval:20.0];
                        }
                        
                        es_respond_result_t res =
                            es_respond_auth_result(clt, copiedMsg, authResult, false);
                            
                        if(ES_RESPOND_RESULT_SUCCESS != res) {
                            LOG_ERROR("es_respond_auth_result: %d", res);
                        }
                            
                        es_free_message(copiedMsg);
                    }
                );
                return;
            }
                
            es_free_message(copiedMsg);
        };
        
        // Create a new client with an associated event message handler.
        // Requires 'com.apple.developer.endpoint-security.client' entitlement.
        es_new_client_result_t res = es_new_client(&g_client, (argc > 0) ? deferedHandler : serialHandler);
        

        if(ES_NEW_CLIENT_RESULT_SUCCESS != res) {
            if(ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED == res) {
               LOG_ERROR("Application requires 'com.apple.developer.endpoint-security.client' entitlement");
            } else if(ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED == res) {
                LOG_ERROR("Application needs to run as root (and SIP disabled).");
            } else {
                LOG_ERROR("es_new_client: %d", res);
            }
            
            return 1;
        }
        
        // Cache needs to be explicitly cleared between program invocations
        es_clear_cache_result_t resCache = es_clear_cache(g_client);
        if(ES_CLEAR_CACHE_RESULT_SUCCESS != resCache) {
            LOG_ERROR("es_clear_cache: %d", resCache);
            return 1;
        }
        
        // Subscribe to the events we're interested in
        es_event_type_t events[] = {
            ES_EVENT_TYPE_AUTH_EXEC
          , ES_EVENT_TYPE_NOTIFY_FORK
        };
        
        es_return_t subscribed = es_subscribe(g_client,
                                       events,
                                       (sizeof(events) / sizeof((events)[0])) // Event count
                                       );
        
        if(ES_RETURN_ERROR == subscribed) {
            LOG_ERROR("es_subscribe: ES_RETURN_ERROR");
            return 1;
        }
        
        dispatch_main();
    }
    
    return 0;
}
