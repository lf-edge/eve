use std::cmp;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::collections::HashMap;
use xcb::{ self, Atom };
use ::{ INCR_CHUNK_SIZE, Context, SetMap };

macro_rules! try_continue {
    ( $expr:expr ) => {
        match $expr {
            Some(val) => val,
            None => continue
        }
    };
}

struct IncrState {
    selection: Atom,
    requestor: Atom,
    property: Atom,
    pos: usize
}

pub fn run(context: &Arc<Context>, setmap: &SetMap, max_length: usize, receiver: &Receiver<Atom>) {
    let mut incr_map = HashMap::new();
    let mut state_map = HashMap::new();

    while let Some(event) = context.connection.wait_for_event() {
        while let Ok(selection) = receiver.try_recv() {
            if let Some(property) = incr_map.remove(&selection) {
                state_map.remove(&property);
            }
        }

        match event.response_type() & !0x80 {
            xcb::SELECTION_REQUEST => {
                let event = unsafe { xcb::cast_event::<xcb::SelectionRequestEvent>(&event) };
                let read_map = try_continue!(setmap.read().ok());
                let &(target, ref value) = try_continue!(read_map.get(&event.selection()));

                if event.target() == context.atoms.targets {
                    xcb::change_property(
                        &context.connection, xcb::PROP_MODE_REPLACE as u8,
                        event.requestor(), event.property(), xcb::ATOM_ATOM, 32,
                        &[context.atoms.targets, target]
                    );
                } else if value.len() < max_length - 24 {
                    xcb::change_property(
                        &context.connection, xcb::PROP_MODE_REPLACE as u8,
                        event.requestor(), event.property(), target, 8,
                        value
                    );
                } else {
                    xcb::change_window_attributes(
                        &context.connection, event.requestor(),
                        &[(xcb::CW_EVENT_MASK, xcb::EVENT_MASK_PROPERTY_CHANGE)]
                    );
                    xcb::change_property(
                        &context.connection, xcb::PROP_MODE_REPLACE as u8,
                        event.requestor(), event.property(), context.atoms.incr, 32,
                        &[0u8; 0]
                    );

                    incr_map.insert(event.selection(), event.property());
                    state_map.insert(
                        event.property(),
                        IncrState {
                            selection: event.selection(),
                            requestor: event.requestor(),
                            property: event.property(),
                            pos: 0
                        }
                    );
                }

                xcb::send_event(
                    &context.connection, false, event.requestor(), 0,
                    &xcb::SelectionNotifyEvent::new(
                        event.time(),
                        event.requestor(),
                        event.selection(),
                        event.target(),
                        event.property()
                    )
                );
                context.connection.flush();
            },
            xcb::PROPERTY_NOTIFY => {
                let event = unsafe { xcb::cast_event::<xcb::PropertyNotifyEvent>(&event) };
                if event.state() != xcb::PROPERTY_DELETE as u8 { continue };

                let is_end = {
                    let state = try_continue!(state_map.get_mut(&event.atom()));
                    let read_setmap = try_continue!(setmap.read().ok());
                    let &(target, ref value) = try_continue!(read_setmap.get(&state.selection));

                    let len = cmp::min(INCR_CHUNK_SIZE, value.len() - state.pos);
                    xcb::change_property(
                        &context.connection, xcb::PROP_MODE_REPLACE as u8,
                        state.requestor, state.property, target, 8,
                        &value[state.pos..][..len]
                    );

                    state.pos += len;
                    len == 0
                };

                if is_end {
                    state_map.remove(&event.atom());
                }
                context.connection.flush();
            },
            xcb::SELECTION_CLEAR => {
                let event = unsafe { xcb::cast_event::<xcb::SelectionClearEvent>(&event) };
                if let Some(property) = incr_map.remove(&event.selection()) {
                    state_map.remove(&property);
                }
                if let Ok(mut write_setmap) = setmap.write() {
                    write_setmap.remove(&event.selection());
                }
            },
            _ => ()
        }
    }
}
