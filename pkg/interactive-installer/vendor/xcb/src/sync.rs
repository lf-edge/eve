// Generated automatically from sync.xml by rs_client.py version 0.8.2.
// Do not edit!

#![allow(unused_unsafe)]

use base;
use xproto;
use ffi::base::*;
use ffi::sync::*;
use ffi::xproto::*;
use libc::{self, c_char, c_int, c_uint, c_void};
use std;
use std::iter::Iterator;


pub fn id() -> &'static mut base::Extension {
    unsafe {
        &mut xcb_sync_id
    }
}

pub const MAJOR_VERSION: u32 = 3;
pub const MINOR_VERSION: u32 = 1;

pub type Alarm = xcb_sync_alarm_t;

pub type Alarmstate = u32;
pub const ALARMSTATE_ACTIVE   : Alarmstate = 0x00;
pub const ALARMSTATE_INACTIVE : Alarmstate = 0x01;
pub const ALARMSTATE_DESTROYED: Alarmstate = 0x02;

pub type Counter = xcb_sync_counter_t;

pub type Fence = xcb_sync_fence_t;

pub type Testtype = u32;
pub const TESTTYPE_POSITIVE_TRANSITION: Testtype = 0x00;
pub const TESTTYPE_NEGATIVE_TRANSITION: Testtype = 0x01;
pub const TESTTYPE_POSITIVE_COMPARISON: Testtype = 0x02;
pub const TESTTYPE_NEGATIVE_COMPARISON: Testtype = 0x03;

pub type Valuetype = u32;
pub const VALUETYPE_ABSOLUTE: Valuetype = 0x00;
pub const VALUETYPE_RELATIVE: Valuetype = 0x01;

pub type Ca = u32;
pub const CA_COUNTER   : Ca = 0x01;
pub const CA_VALUE_TYPE: Ca = 0x02;
pub const CA_VALUE     : Ca = 0x04;
pub const CA_TEST_TYPE : Ca = 0x08;
pub const CA_DELTA     : Ca = 0x10;
pub const CA_EVENTS    : Ca = 0x20;

pub struct CounterError {
    pub base: base::Error<xcb_sync_counter_error_t>
}

pub struct AlarmError {
    pub base: base::Error<xcb_sync_alarm_error_t>
}



#[derive(Copy, Clone)]
pub struct Int64 {
    pub base: xcb_sync_int64_t,
}

impl Int64 {
    #[allow(unused_unsafe)]
    pub fn new(hi: i32,
               lo: u32)
            -> Int64 {
        unsafe {
            Int64 {
                base: xcb_sync_int64_t {
                    hi: hi,
                    lo: lo,
                }
            }
        }
    }
    pub fn hi(&self) -> i32 {
        unsafe {
            self.base.hi
        }
    }
    pub fn lo(&self) -> u32 {
        unsafe {
            self.base.lo
        }
    }
}

pub type Int64Iterator = xcb_sync_int64_iterator_t;

impl Iterator for Int64Iterator {
    type Item = Int64;
    fn next(&mut self) -> std::option::Option<Int64> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_sync_int64_iterator_t;
                let data = (*iter).data;
                xcb_sync_int64_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub type Systemcounter<'a> = base::StructPtr<'a, xcb_sync_systemcounter_t>;

impl<'a> Systemcounter<'a> {
    pub fn counter(&self) -> Counter {
        unsafe {
            (*self.ptr).counter
        }
    }
    pub fn resolution(&self) -> Int64 {
        unsafe {
            std::mem::transmute((*self.ptr).resolution)
        }
    }
    pub fn name_len(&self) -> u16 {
        unsafe {
            (*self.ptr).name_len
        }
    }
    pub fn name(&self) -> &str {
        unsafe {
            let field = self.ptr;
            let len = xcb_sync_systemcounter_name_length(field) as usize;
            let data = xcb_sync_systemcounter_name(field);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            // should we check what comes from X?
            std::str::from_utf8_unchecked(&slice)
        }
    }
}

pub type SystemcounterIterator<'a> = xcb_sync_systemcounter_iterator_t<'a>;

impl<'a> Iterator for SystemcounterIterator<'a> {
    type Item = Systemcounter<'a>;
    fn next(&mut self) -> std::option::Option<Systemcounter<'a>> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_sync_systemcounter_iterator_t;
                let data = (*iter).data;
                xcb_sync_systemcounter_next(iter);
                Some(std::mem::transmute(data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Trigger {
    pub base: xcb_sync_trigger_t,
}

impl Trigger {
    #[allow(unused_unsafe)]
    pub fn new(counter:    Counter,
               wait_type:  u32,
               wait_value: Int64,
               test_type:  u32)
            -> Trigger {
        unsafe {
            Trigger {
                base: xcb_sync_trigger_t {
                    counter:    counter,
                    wait_type:  wait_type,
                    wait_value: std::mem::transmute(wait_value),
                    test_type:  test_type,
                }
            }
        }
    }
    pub fn counter(&self) -> Counter {
        unsafe {
            self.base.counter
        }
    }
    pub fn wait_type(&self) -> u32 {
        unsafe {
            self.base.wait_type
        }
    }
    pub fn wait_value(&self) -> Int64 {
        unsafe {
            std::mem::transmute(self.base.wait_value)
        }
    }
    pub fn test_type(&self) -> u32 {
        unsafe {
            self.base.test_type
        }
    }
}

pub type TriggerIterator = xcb_sync_trigger_iterator_t;

impl Iterator for TriggerIterator {
    type Item = Trigger;
    fn next(&mut self) -> std::option::Option<Trigger> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_sync_trigger_iterator_t;
                let data = (*iter).data;
                xcb_sync_trigger_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct Waitcondition {
    pub base: xcb_sync_waitcondition_t,
}

impl Waitcondition {
    #[allow(unused_unsafe)]
    pub fn new(trigger:         Trigger,
               event_threshold: Int64)
            -> Waitcondition {
        unsafe {
            Waitcondition {
                base: xcb_sync_waitcondition_t {
                    trigger:         std::mem::transmute(trigger),
                    event_threshold: std::mem::transmute(event_threshold),
                }
            }
        }
    }
    pub fn trigger(&self) -> Trigger {
        unsafe {
            std::mem::transmute(self.base.trigger)
        }
    }
    pub fn event_threshold(&self) -> Int64 {
        unsafe {
            std::mem::transmute(self.base.event_threshold)
        }
    }
}

pub type WaitconditionIterator = xcb_sync_waitcondition_iterator_t;

impl Iterator for WaitconditionIterator {
    type Item = Waitcondition;
    fn next(&mut self) -> std::option::Option<Waitcondition> {
        if self.rem == 0 { None }
        else {
            unsafe {
                let iter = self as *mut xcb_sync_waitcondition_iterator_t;
                let data = (*iter).data;
                xcb_sync_waitcondition_next(iter);
                Some(std::mem::transmute(*data))
            }
        }
    }
}

pub const COUNTER: u8 = 0;

pub const ALARM: u8 = 1;

pub const INITIALIZE: u8 = 0;

pub type InitializeCookie<'a> = base::Cookie<'a, xcb_sync_initialize_cookie_t>;

impl<'a> InitializeCookie<'a> {
    pub fn get_reply(&self) -> Result<InitializeReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = InitializeReply {
                    ptr: xcb_sync_initialize_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( InitializeReply {
                    ptr: xcb_sync_initialize_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type InitializeReply = base::Reply<xcb_sync_initialize_reply_t>;

impl InitializeReply {
    pub fn major_version(&self) -> u8 {
        unsafe {
            (*self.ptr).major_version
        }
    }
    pub fn minor_version(&self) -> u8 {
        unsafe {
            (*self.ptr).minor_version
        }
    }
}

pub fn initialize<'a>(c                    : &'a base::Connection,
                      desired_major_version: u8,
                      desired_minor_version: u8)
        -> InitializeCookie<'a> {
    unsafe {
        let cookie = xcb_sync_initialize(c.get_raw_conn(),
                                         desired_major_version as u8,  // 0
                                         desired_minor_version as u8);  // 1
        InitializeCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn initialize_unchecked<'a>(c                    : &'a base::Connection,
                                desired_major_version: u8,
                                desired_minor_version: u8)
        -> InitializeCookie<'a> {
    unsafe {
        let cookie = xcb_sync_initialize_unchecked(c.get_raw_conn(),
                                                   desired_major_version as u8,  // 0
                                                   desired_minor_version as u8);  // 1
        InitializeCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const LIST_SYSTEM_COUNTERS: u8 = 1;

pub type ListSystemCountersCookie<'a> = base::Cookie<'a, xcb_sync_list_system_counters_cookie_t>;

impl<'a> ListSystemCountersCookie<'a> {
    pub fn get_reply(&self) -> Result<ListSystemCountersReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = ListSystemCountersReply {
                    ptr: xcb_sync_list_system_counters_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( ListSystemCountersReply {
                    ptr: xcb_sync_list_system_counters_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type ListSystemCountersReply = base::Reply<xcb_sync_list_system_counters_reply_t>;

impl ListSystemCountersReply {
    pub fn counters_len(&self) -> u32 {
        unsafe {
            (*self.ptr).counters_len
        }
    }
    pub fn counters(&self) -> SystemcounterIterator {
        unsafe {
            xcb_sync_list_system_counters_counters_iterator(self.ptr)
        }
    }
}

pub fn list_system_counters<'a>(c: &'a base::Connection)
        -> ListSystemCountersCookie<'a> {
    unsafe {
        let cookie = xcb_sync_list_system_counters(c.get_raw_conn());
        ListSystemCountersCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn list_system_counters_unchecked<'a>(c: &'a base::Connection)
        -> ListSystemCountersCookie<'a> {
    unsafe {
        let cookie = xcb_sync_list_system_counters_unchecked(c.get_raw_conn());
        ListSystemCountersCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_COUNTER: u8 = 2;

pub fn create_counter<'a>(c            : &'a base::Connection,
                          id           : Counter,
                          initial_value: Int64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_create_counter(c.get_raw_conn(),
                                             id as xcb_sync_counter_t,  // 0
                                             initial_value.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_counter_checked<'a>(c            : &'a base::Connection,
                                  id           : Counter,
                                  initial_value: Int64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_create_counter_checked(c.get_raw_conn(),
                                                     id as xcb_sync_counter_t,  // 0
                                                     initial_value.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_COUNTER: u8 = 6;

pub fn destroy_counter<'a>(c      : &'a base::Connection,
                           counter: Counter)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_destroy_counter(c.get_raw_conn(),
                                              counter as xcb_sync_counter_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_counter_checked<'a>(c      : &'a base::Connection,
                                   counter: Counter)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_destroy_counter_checked(c.get_raw_conn(),
                                                      counter as xcb_sync_counter_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_COUNTER: u8 = 5;

pub type QueryCounterCookie<'a> = base::Cookie<'a, xcb_sync_query_counter_cookie_t>;

impl<'a> QueryCounterCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryCounterReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryCounterReply {
                    ptr: xcb_sync_query_counter_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryCounterReply {
                    ptr: xcb_sync_query_counter_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryCounterReply = base::Reply<xcb_sync_query_counter_reply_t>;

impl QueryCounterReply {
    pub fn counter_value(&self) -> Int64 {
        unsafe {
            std::mem::transmute((*self.ptr).counter_value)
        }
    }
}

pub fn query_counter<'a>(c      : &'a base::Connection,
                         counter: Counter)
        -> QueryCounterCookie<'a> {
    unsafe {
        let cookie = xcb_sync_query_counter(c.get_raw_conn(),
                                            counter as xcb_sync_counter_t);  // 0
        QueryCounterCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_counter_unchecked<'a>(c      : &'a base::Connection,
                                   counter: Counter)
        -> QueryCounterCookie<'a> {
    unsafe {
        let cookie = xcb_sync_query_counter_unchecked(c.get_raw_conn(),
                                                      counter as xcb_sync_counter_t);  // 0
        QueryCounterCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const AWAIT: u8 = 7;

pub fn await<'a>(c        : &'a base::Connection,
                 wait_list: &[Waitcondition])
        -> base::VoidCookie<'a> {
    unsafe {
        let wait_list_len = wait_list.len();
        let wait_list_ptr = wait_list.as_ptr();
        let cookie = xcb_sync_await(c.get_raw_conn(),
                                    wait_list_len as u32,  // 0
                                    wait_list_ptr as *const xcb_sync_waitcondition_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn await_checked<'a>(c        : &'a base::Connection,
                         wait_list: &[Waitcondition])
        -> base::VoidCookie<'a> {
    unsafe {
        let wait_list_len = wait_list.len();
        let wait_list_ptr = wait_list.as_ptr();
        let cookie = xcb_sync_await_checked(c.get_raw_conn(),
                                            wait_list_len as u32,  // 0
                                            wait_list_ptr as *const xcb_sync_waitcondition_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const CHANGE_COUNTER: u8 = 4;

pub fn change_counter<'a>(c      : &'a base::Connection,
                          counter: Counter,
                          amount : Int64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_change_counter(c.get_raw_conn(),
                                             counter as xcb_sync_counter_t,  // 0
                                             amount.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_counter_checked<'a>(c      : &'a base::Connection,
                                  counter: Counter,
                                  amount : Int64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_change_counter_checked(c.get_raw_conn(),
                                                     counter as xcb_sync_counter_t,  // 0
                                                     amount.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const SET_COUNTER: u8 = 3;

pub fn set_counter<'a>(c      : &'a base::Connection,
                       counter: Counter,
                       value  : Int64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_set_counter(c.get_raw_conn(),
                                          counter as xcb_sync_counter_t,  // 0
                                          value.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_counter_checked<'a>(c      : &'a base::Connection,
                               counter: Counter,
                               value  : Int64)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_set_counter_checked(c.get_raw_conn(),
                                                  counter as xcb_sync_counter_t,  // 0
                                                  value.base);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub type CreateAlarmValueList<'a> = base::StructPtr<'a, xcb_sync_create_alarm_value_list_t>;

pub const CREATE_ALARM: u8 = 8;

pub fn create_alarm<'a>(c         : &'a base::Connection,
                        id        : Alarm,
                        value_mask: u32,
                        value_list: std::option::Option<CreateAlarmValueList>)
        -> base::VoidCookie<'a> {
    unsafe {
        let value_list_ptr = match value_list {
            Some(p) => p.ptr as *const xcb_sync_create_alarm_value_list_t,
            None => std::ptr::null()
        };
        let cookie = xcb_sync_create_alarm(c.get_raw_conn(),
                                           id as xcb_sync_alarm_t,  // 0
                                           value_mask as u32,  // 1
                                           value_list_ptr);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_alarm_checked<'a>(c         : &'a base::Connection,
                                id        : Alarm,
                                value_mask: u32,
                                value_list: std::option::Option<CreateAlarmValueList>)
        -> base::VoidCookie<'a> {
    unsafe {
        let value_list_ptr = match value_list {
            Some(p) => p.ptr as *const xcb_sync_create_alarm_value_list_t,
            None => std::ptr::null()
        };
        let cookie = xcb_sync_create_alarm_checked(c.get_raw_conn(),
                                                   id as xcb_sync_alarm_t,  // 0
                                                   value_mask as u32,  // 1
                                                   value_list_ptr);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub type ChangeAlarmValueList<'a> = base::StructPtr<'a, xcb_sync_change_alarm_value_list_t>;

pub const CHANGE_ALARM: u8 = 9;

pub fn change_alarm<'a>(c         : &'a base::Connection,
                        id        : Alarm,
                        value_mask: u32,
                        value_list: std::option::Option<ChangeAlarmValueList>)
        -> base::VoidCookie<'a> {
    unsafe {
        let value_list_ptr = match value_list {
            Some(p) => p.ptr as *const xcb_sync_change_alarm_value_list_t,
            None => std::ptr::null()
        };
        let cookie = xcb_sync_change_alarm(c.get_raw_conn(),
                                           id as xcb_sync_alarm_t,  // 0
                                           value_mask as u32,  // 1
                                           value_list_ptr);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn change_alarm_checked<'a>(c         : &'a base::Connection,
                                id        : Alarm,
                                value_mask: u32,
                                value_list: std::option::Option<ChangeAlarmValueList>)
        -> base::VoidCookie<'a> {
    unsafe {
        let value_list_ptr = match value_list {
            Some(p) => p.ptr as *const xcb_sync_change_alarm_value_list_t,
            None => std::ptr::null()
        };
        let cookie = xcb_sync_change_alarm_checked(c.get_raw_conn(),
                                                   id as xcb_sync_alarm_t,  // 0
                                                   value_mask as u32,  // 1
                                                   value_list_ptr);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_ALARM: u8 = 11;

pub fn destroy_alarm<'a>(c    : &'a base::Connection,
                         alarm: Alarm)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_destroy_alarm(c.get_raw_conn(),
                                            alarm as xcb_sync_alarm_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_alarm_checked<'a>(c    : &'a base::Connection,
                                 alarm: Alarm)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_destroy_alarm_checked(c.get_raw_conn(),
                                                    alarm as xcb_sync_alarm_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_ALARM: u8 = 10;

pub type QueryAlarmCookie<'a> = base::Cookie<'a, xcb_sync_query_alarm_cookie_t>;

impl<'a> QueryAlarmCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryAlarmReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryAlarmReply {
                    ptr: xcb_sync_query_alarm_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryAlarmReply {
                    ptr: xcb_sync_query_alarm_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryAlarmReply = base::Reply<xcb_sync_query_alarm_reply_t>;

impl QueryAlarmReply {
    pub fn trigger(&self) -> Trigger {
        unsafe {
            std::mem::transmute((*self.ptr).trigger)
        }
    }
    pub fn delta(&self) -> Int64 {
        unsafe {
            std::mem::transmute((*self.ptr).delta)
        }
    }
    pub fn events(&self) -> bool {
        unsafe {
            (*self.ptr).events != 0
        }
    }
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
}

pub fn query_alarm<'a>(c    : &'a base::Connection,
                       alarm: Alarm)
        -> QueryAlarmCookie<'a> {
    unsafe {
        let cookie = xcb_sync_query_alarm(c.get_raw_conn(),
                                          alarm as xcb_sync_alarm_t);  // 0
        QueryAlarmCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_alarm_unchecked<'a>(c    : &'a base::Connection,
                                 alarm: Alarm)
        -> QueryAlarmCookie<'a> {
    unsafe {
        let cookie = xcb_sync_query_alarm_unchecked(c.get_raw_conn(),
                                                    alarm as xcb_sync_alarm_t);  // 0
        QueryAlarmCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const SET_PRIORITY: u8 = 12;

pub fn set_priority<'a>(c       : &'a base::Connection,
                        id      : u32,
                        priority: i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_set_priority(c.get_raw_conn(),
                                           id as u32,  // 0
                                           priority as i32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn set_priority_checked<'a>(c       : &'a base::Connection,
                                id      : u32,
                                priority: i32)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_set_priority_checked(c.get_raw_conn(),
                                                   id as u32,  // 0
                                                   priority as i32);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const GET_PRIORITY: u8 = 13;

pub type GetPriorityCookie<'a> = base::Cookie<'a, xcb_sync_get_priority_cookie_t>;

impl<'a> GetPriorityCookie<'a> {
    pub fn get_reply(&self) -> Result<GetPriorityReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = GetPriorityReply {
                    ptr: xcb_sync_get_priority_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( GetPriorityReply {
                    ptr: xcb_sync_get_priority_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type GetPriorityReply = base::Reply<xcb_sync_get_priority_reply_t>;

impl GetPriorityReply {
    pub fn priority(&self) -> i32 {
        unsafe {
            (*self.ptr).priority
        }
    }
}

pub fn get_priority<'a>(c : &'a base::Connection,
                        id: u32)
        -> GetPriorityCookie<'a> {
    unsafe {
        let cookie = xcb_sync_get_priority(c.get_raw_conn(),
                                           id as u32);  // 0
        GetPriorityCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn get_priority_unchecked<'a>(c : &'a base::Connection,
                                  id: u32)
        -> GetPriorityCookie<'a> {
    unsafe {
        let cookie = xcb_sync_get_priority_unchecked(c.get_raw_conn(),
                                                     id as u32);  // 0
        GetPriorityCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const CREATE_FENCE: u8 = 14;

pub fn create_fence<'a>(c                  : &'a base::Connection,
                        drawable           : xproto::Drawable,
                        fence              : Fence,
                        initially_triggered: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_create_fence(c.get_raw_conn(),
                                           drawable as xcb_drawable_t,  // 0
                                           fence as xcb_sync_fence_t,  // 1
                                           initially_triggered as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn create_fence_checked<'a>(c                  : &'a base::Connection,
                                drawable           : xproto::Drawable,
                                fence              : Fence,
                                initially_triggered: bool)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_create_fence_checked(c.get_raw_conn(),
                                                   drawable as xcb_drawable_t,  // 0
                                                   fence as xcb_sync_fence_t,  // 1
                                                   initially_triggered as u8);  // 2
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const TRIGGER_FENCE: u8 = 15;

pub fn trigger_fence<'a>(c    : &'a base::Connection,
                         fence: Fence)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_trigger_fence(c.get_raw_conn(),
                                            fence as xcb_sync_fence_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn trigger_fence_checked<'a>(c    : &'a base::Connection,
                                 fence: Fence)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_trigger_fence_checked(c.get_raw_conn(),
                                                    fence as xcb_sync_fence_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const RESET_FENCE: u8 = 16;

pub fn reset_fence<'a>(c    : &'a base::Connection,
                       fence: Fence)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_reset_fence(c.get_raw_conn(),
                                          fence as xcb_sync_fence_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn reset_fence_checked<'a>(c    : &'a base::Connection,
                               fence: Fence)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_reset_fence_checked(c.get_raw_conn(),
                                                  fence as xcb_sync_fence_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const DESTROY_FENCE: u8 = 17;

pub fn destroy_fence<'a>(c    : &'a base::Connection,
                         fence: Fence)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_destroy_fence(c.get_raw_conn(),
                                            fence as xcb_sync_fence_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn destroy_fence_checked<'a>(c    : &'a base::Connection,
                                 fence: Fence)
        -> base::VoidCookie<'a> {
    unsafe {
        let cookie = xcb_sync_destroy_fence_checked(c.get_raw_conn(),
                                                    fence as xcb_sync_fence_t);  // 0
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const QUERY_FENCE: u8 = 18;

pub type QueryFenceCookie<'a> = base::Cookie<'a, xcb_sync_query_fence_cookie_t>;

impl<'a> QueryFenceCookie<'a> {
    pub fn get_reply(&self) -> Result<QueryFenceReply, base::GenericError> {
        unsafe {
            if self.checked {
                let mut err: *mut xcb_generic_error_t = std::ptr::null_mut();
                let reply = QueryFenceReply {
                    ptr: xcb_sync_query_fence_reply (self.conn.get_raw_conn(), self.cookie, &mut err)
                };
                if err.is_null() { Ok (reply) }
                else { Err(base::GenericError { ptr: err }) }
            } else {
                Ok( QueryFenceReply {
                    ptr: xcb_sync_query_fence_reply (self.conn.get_raw_conn(), self.cookie,
                            std::ptr::null_mut())
                })
            }
        }
    }
}

pub type QueryFenceReply = base::Reply<xcb_sync_query_fence_reply_t>;

impl QueryFenceReply {
    pub fn triggered(&self) -> bool {
        unsafe {
            (*self.ptr).triggered != 0
        }
    }
}

pub fn query_fence<'a>(c    : &'a base::Connection,
                       fence: Fence)
        -> QueryFenceCookie<'a> {
    unsafe {
        let cookie = xcb_sync_query_fence(c.get_raw_conn(),
                                          fence as xcb_sync_fence_t);  // 0
        QueryFenceCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub fn query_fence_unchecked<'a>(c    : &'a base::Connection,
                                 fence: Fence)
        -> QueryFenceCookie<'a> {
    unsafe {
        let cookie = xcb_sync_query_fence_unchecked(c.get_raw_conn(),
                                                    fence as xcb_sync_fence_t);  // 0
        QueryFenceCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub const AWAIT_FENCE: u8 = 19;

pub fn await_fence<'a>(c         : &'a base::Connection,
                       fence_list: &[Fence])
        -> base::VoidCookie<'a> {
    unsafe {
        let fence_list_len = fence_list.len();
        let fence_list_ptr = fence_list.as_ptr();
        let cookie = xcb_sync_await_fence(c.get_raw_conn(),
                                          fence_list_len as u32,  // 0
                                          fence_list_ptr as *const xcb_sync_fence_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: false
        }
    }
}

pub fn await_fence_checked<'a>(c         : &'a base::Connection,
                               fence_list: &[Fence])
        -> base::VoidCookie<'a> {
    unsafe {
        let fence_list_len = fence_list.len();
        let fence_list_ptr = fence_list.as_ptr();
        let cookie = xcb_sync_await_fence_checked(c.get_raw_conn(),
                                                  fence_list_len as u32,  // 0
                                                  fence_list_ptr as *const xcb_sync_fence_t);  // 1
        base::VoidCookie {
            cookie:  cookie,
            conn:    c,
            checked: true
        }
    }
}

pub const COUNTER_NOTIFY: u8 = 0;

pub type CounterNotifyEvent = base::Event<xcb_sync_counter_notify_event_t>;

impl CounterNotifyEvent {
    pub fn kind(&self) -> u8 {
        unsafe {
            (*self.ptr).kind
        }
    }
    pub fn counter(&self) -> Counter {
        unsafe {
            (*self.ptr).counter
        }
    }
    pub fn wait_value(&self) -> Int64 {
        unsafe {
            std::mem::transmute((*self.ptr).wait_value)
        }
    }
    pub fn counter_value(&self) -> Int64 {
        unsafe {
            std::mem::transmute((*self.ptr).counter_value)
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn count(&self) -> u16 {
        unsafe {
            (*self.ptr).count
        }
    }
    pub fn destroyed(&self) -> bool {
        unsafe {
            (*self.ptr).destroyed != 0
        }
    }
    /// Constructs a new CounterNotifyEvent
    /// `response_type` will be set automatically to COUNTER_NOTIFY
    pub fn new(kind: u8,
               counter: Counter,
               wait_value: Int64,
               counter_value: Int64,
               timestamp: xproto::Timestamp,
               count: u16,
               destroyed: bool)
            -> CounterNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_sync_counter_notify_event_t;
            (*raw).response_type = COUNTER_NOTIFY;
            (*raw).kind = kind;
            (*raw).counter = counter;
            (*raw).wait_value = wait_value.base;
            (*raw).counter_value = counter_value.base;
            (*raw).timestamp = timestamp;
            (*raw).count = count;
            (*raw).destroyed = if destroyed { 1 } else { 0 };
            CounterNotifyEvent {
                ptr: raw
            }
        }
    }
}

pub const ALARM_NOTIFY: u8 = 1;

pub type AlarmNotifyEvent = base::Event<xcb_sync_alarm_notify_event_t>;

impl AlarmNotifyEvent {
    pub fn kind(&self) -> u8 {
        unsafe {
            (*self.ptr).kind
        }
    }
    pub fn alarm(&self) -> Alarm {
        unsafe {
            (*self.ptr).alarm
        }
    }
    pub fn counter_value(&self) -> Int64 {
        unsafe {
            std::mem::transmute((*self.ptr).counter_value)
        }
    }
    pub fn alarm_value(&self) -> Int64 {
        unsafe {
            std::mem::transmute((*self.ptr).alarm_value)
        }
    }
    pub fn timestamp(&self) -> xproto::Timestamp {
        unsafe {
            (*self.ptr).timestamp
        }
    }
    pub fn state(&self) -> u8 {
        unsafe {
            (*self.ptr).state
        }
    }
    /// Constructs a new AlarmNotifyEvent
    /// `response_type` will be set automatically to ALARM_NOTIFY
    pub fn new(kind: u8,
               alarm: Alarm,
               counter_value: Int64,
               alarm_value: Int64,
               timestamp: xproto::Timestamp,
               state: u8)
            -> AlarmNotifyEvent {
        unsafe {
            let raw = libc::malloc(32 as usize) as *mut xcb_sync_alarm_notify_event_t;
            (*raw).response_type = ALARM_NOTIFY;
            (*raw).kind = kind;
            (*raw).alarm = alarm;
            (*raw).counter_value = counter_value.base;
            (*raw).alarm_value = alarm_value.base;
            (*raw).timestamp = timestamp;
            (*raw).state = state;
            AlarmNotifyEvent {
                ptr: raw
            }
        }
    }
}
