pub extern crate xcb;

pub mod error;
mod run;

use std::thread;
use std::time::{ Duration, Instant };
use std::sync::{ Arc, RwLock };
use std::sync::mpsc::{ Sender, channel };
use std::collections::HashMap;
use xcb::{ Connection, Window, Atom };
use xcb::base::ConnError;
use error::Error;

pub const INCR_CHUNK_SIZE: usize = 4000;
const POLL_DURATION: u64 = 50;
type SetMap = Arc<RwLock<HashMap<Atom, (Atom, Vec<u8>)>>>;

#[derive(Clone, Debug)]
pub struct Atoms {
    pub primary: Atom,
    pub clipboard: Atom,
    pub property: Atom,
    pub targets: Atom,
    pub string: Atom,
    pub utf8_string: Atom,
    pub incr: Atom
}

/// X11 Clipboard
pub struct Clipboard {
    pub getter: Context,
    pub setter: Arc<Context>,
    setmap: SetMap,
    send: Sender<Atom>
}

pub struct Context {
    pub connection: Connection,
    pub screen: i32,
    pub window: Window,
    pub atoms: Atoms
}

#[inline]
fn get_atom(connection: &Connection, name: &str) -> Result<Atom, Error> {
    xcb::intern_atom(connection, false, name)
        .get_reply()
        .map(|reply| reply.atom())
        .map_err(Into::into)
}

impl Context {
    pub fn new(displayname: Option<&str>) -> Result<Self, Error> {
        let (connection, screen) = Connection::connect(displayname)?;
        let window = connection.generate_id();

        {
            let screen = connection.get_setup().roots().nth(screen as usize)
                .ok_or(Error::XcbConn(ConnError::ClosedInvalidScreen))?;
            xcb::create_window(
                &connection,
                xcb::COPY_FROM_PARENT as u8,
                window, screen.root(),
                0, 0, 1, 1,
                0,
                xcb::WINDOW_CLASS_INPUT_OUTPUT as u16,
                screen.root_visual(),
                &[(
                    xcb::CW_EVENT_MASK,
                    xcb::EVENT_MASK_STRUCTURE_NOTIFY | xcb::EVENT_MASK_PROPERTY_CHANGE
                )]
            );
            connection.flush();
        }

        macro_rules! intern_atom {
            ( $name:expr ) => {
                get_atom(&connection, $name)?
            }
        }

        let atoms = Atoms {
            primary: xcb::ATOM_PRIMARY,
            clipboard: intern_atom!("CLIPBOARD"),
            property: intern_atom!("THIS_CLIPBOARD_OUT"),
            targets: intern_atom!("TARGETS"),
            string: xcb::ATOM_STRING,
            utf8_string: intern_atom!("UTF8_STRING"),
            incr: intern_atom!("INCR")
        };

        Ok(Context { connection, screen, window, atoms })
    }

    pub fn get_atom(&self, name: &str) -> Result<Atom, Error> {
        get_atom(&self.connection, name)
    }
}


impl Clipboard {
    /// Create Clipboard.
    pub fn new() -> Result<Self, Error> {
        let getter = Context::new(None)?;
        let setter = Arc::new(Context::new(None)?);
        let setter2 = Arc::clone(&setter);
        let setmap = Arc::new(RwLock::new(HashMap::new()));
        let setmap2 = Arc::clone(&setmap);

        let (sender, receiver) = channel();
        let max_length = setter.connection.get_maximum_request_length() as usize * 4;
        thread::spawn(move || run::run(&setter2, &setmap2, max_length, &receiver));

        Ok(Clipboard { getter, setter, setmap, send: sender })
    }

    fn process_event<T>(&self, buff: &mut Vec<u8>, selection: Atom, target: Atom, property: Atom, timeout: T, use_xfixes: bool, xfixes_event_base: u8)
        -> Result<(), Error>
        where T: Into<Option<Duration>>
    {
        let mut is_incr = false;
        let timeout = timeout.into();
        let start_time =
            if timeout.is_some() { Some(Instant::now()) }
            else { None };

        loop {
            if timeout.into_iter()
                .zip(start_time)
                .next()
                .map(|(timeout, time)| (Instant::now() - time) >= timeout)
                .unwrap_or(false)
            {
                return Err(Error::Timeout);
            }

            let event = match use_xfixes {
                true => {
                    match self.getter.connection.wait_for_event() {
                        Some(event) => event,
                        None => {
                            continue
                        }
                    }
                },
                false => {
                    match self.getter.connection.poll_for_event() {
                        Some(event) => event,
                        None => {
                            thread::park_timeout(Duration::from_millis(POLL_DURATION));
                            continue
                        }
                    }
                }
            };

            let r = event.response_type();

            if use_xfixes && r == (xfixes_event_base + xcb::xfixes::SELECTION_NOTIFY) {
                let event = unsafe { xcb::cast_event::<xcb::xfixes::SelectionNotifyEvent>(&event) };
                xcb::convert_selection(&self.getter.connection, self.getter.window,
                                       selection, target, property,
                                       event.timestamp());
                self.getter.connection.flush();
                continue;
            }

            match r & !0x80 {
                xcb::SELECTION_NOTIFY => {
                    let event = unsafe { xcb::cast_event::<xcb::SelectionNotifyEvent>(&event) };
                    if event.selection() != selection { continue };

                    // Note that setting the property argument to None indicates that the
                    // conversion requested could not be made.
                    if event.property() == xcb::ATOM_NONE {
                        break;
                    }

                    let reply =
                        xcb::get_property(
                            &self.getter.connection, false, self.getter.window,
                            event.property(), xcb::ATOM_ANY, buff.len() as u32, ::std::u32::MAX // FIXME reasonable buffer size
                        )
                        .get_reply()?;

                    if reply.type_() == self.getter.atoms.incr {
                        if let Some(&size) = reply.value::<i32>().get(0) {
                            buff.reserve(size as usize);
                        }
                        xcb::delete_property(&self.getter.connection, self.getter.window, property);
                        self.getter.connection.flush();
                        is_incr = true;
                        continue
                    } else if reply.type_() != target {
                        // FIXME
                        //
                        // In order not to break api compatibility, we can't add a new ErrorKind.
                        // This will become an Error in the next version.
                        return Ok(());
                    }

                    buff.extend_from_slice(reply.value());
                    break
                },
                xcb::PROPERTY_NOTIFY if is_incr => {
                    let event = unsafe { xcb::cast_event::<xcb::PropertyNotifyEvent>(&event) };
                    if event.state() != xcb::PROPERTY_NEW_VALUE as u8 { continue };

                    let length =
                        xcb::get_property(
                            &self.getter.connection, false, self.getter.window,
                            property, xcb::ATOM_ANY, 0, 0
                        )
                        .get_reply()
                        .map(|reply| reply.bytes_after())?;

                    let reply =
                        xcb::get_property(
                            &self.getter.connection, true, self.getter.window,
                            property, xcb::ATOM_ANY, 0, length
                        )
                        .get_reply()?;

                    if reply.type_() != target { continue };

                    if reply.value_len() != 0 {
                        buff.extend_from_slice(reply.value());
                    } else {
                        break
                    }
                },
                _ => ()
            }
        }
        Ok(())
    }

    /// load value.
    pub fn load<T>(&self, selection: Atom, target: Atom, property: Atom, timeout: T)
        -> Result<Vec<u8>, Error>
        where T: Into<Option<Duration>>
    {
        let mut buff = Vec::new();
        let timeout = timeout.into();

        xcb::convert_selection(
            &self.getter.connection, self.getter.window,
            selection, target, property,
            xcb::CURRENT_TIME
                // FIXME ^
                // Clients should not use CurrentTime for the time argument of a ConvertSelection request.
                // Instead, they should use the timestamp of the event that caused the request to be made.
        );
        self.getter.connection.flush();

        self.process_event(&mut buff, selection, target, property, timeout, false, 0)?;
        xcb::delete_property(&self.getter.connection, self.getter.window, property);
        self.getter.connection.flush();
        Ok(buff)
    }

    /// wait for a new value and load it
    pub fn load_wait(&self, selection: Atom, target: Atom, property: Atom)
        -> Result<Vec<u8>, Error>
    {
        let mut buff = Vec::new();

        let screen = &self.getter.connection.get_setup().roots()
            .nth(self.getter.screen as usize)
            .ok_or(Error::XcbConn(ConnError::ClosedInvalidScreen))?;

        let xfixes = xcb::query_extension(
            &self.getter.connection, "XFIXES").get_reply()?;
        assert!(xfixes.present());
        xcb::xfixes::query_version(&self.getter.connection, 5, 0);
        // Clear selection sources...
        xcb::xfixes::select_selection_input(
            &self.getter.connection, screen.root(), self.getter.atoms.primary, 0);
        xcb::xfixes::select_selection_input(
            &self.getter.connection, screen.root(), self.getter.atoms.clipboard, 0);
        // ...and set the one requested now
        xcb::xfixes::select_selection_input(
            &self.getter.connection, screen.root(), selection,
            xcb::xfixes::SELECTION_EVENT_MASK_SET_SELECTION_OWNER |
            xcb::xfixes::SELECTION_EVENT_MASK_SELECTION_CLIENT_CLOSE |
            xcb::xfixes::SELECTION_EVENT_MASK_SELECTION_WINDOW_DESTROY);
        self.getter.connection.flush();

        self.process_event(&mut buff, selection, target, property, None, true, xfixes.first_event())?;
        xcb::delete_property(&self.getter.connection, self.getter.window, property);
        self.getter.connection.flush();
        Ok(buff)
    }

    /// store value.
    pub fn store<T: Into<Vec<u8>>>(&self, selection: Atom, target: Atom, value: T)
        -> Result<(), Error>
    {
        self.send.send(selection)?;
        self.setmap
            .write()
            .map_err(|_| Error::Lock)?
            .insert(selection, (target, value.into()));

        xcb::set_selection_owner(
            &self.setter.connection,
            self.setter.window, selection,
            xcb::CURRENT_TIME
        );

        self.setter.connection.flush();

        if xcb::get_selection_owner(&self.setter.connection, selection)
            .get_reply()
            .map(|reply| reply.owner() == self.setter.window)
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err(Error::Owner)
        }
    }
}
