/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use anyhow::Result;
use cursive::reexports::log;
use std::fmt::Debug;

#[derive(Debug)]
pub enum AbortReason {
    User,
    Error(anyhow::Error),
}
pub enum Transition<M> {
    DoNothing,
    ChangeState(Box<dyn State<M>>),
    Abort(AbortReason),
}

impl<M> std::fmt::Debug for Transition<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoNothing => write!(f, "DoNothing"),
            Self::ChangeState(arg0) => f.debug_tuple("ChangeState").field(&arg0.name()).finish(),
            Self::Abort(arg0) => f.debug_tuple("Abort").field(arg0).finish(),
        }
    }
}
pub trait State<M>: StateName<M>
where
    M: Debug,
{
    fn on_event(&mut self, fsm: &mut dyn FsmMsgHelper<M>, msg: M) -> Result<Transition<M>> {
        log::info!("{}.on_event({:?})", self.name(), msg);
        println!("{}.on_event({:?})", self.name(), msg);
        Ok(Transition::DoNothing)
    }
    fn on_enter(&mut self, fsm: &mut dyn FsmMsgHelper<M>) -> Result<()> {
        log::info!("{}.on_enter()", self.name());
        println!("{}.on_enter()", self.name());
        Ok(())
    }
    fn on_exit(&mut self, fsm: &mut dyn FsmMsgHelper<M>) -> Result<()> {
        log::info!("{}.on_exit()", self.name());
        println!("{}.on_exit()", self.name());
        Ok(())
    }
}

pub trait StateName<M> {
    fn name(&self) -> String {
        std::any::type_name::<Self>().to_string()
    }
}

impl<T, M> StateName<M> for T
where
    T: State<M>,
    M: Debug,
{
}

pub trait FsmMsgHelper<M> {
    fn send_to_self(&mut self, msg: M) -> Result<()>;
    fn send_to_ui(&mut self, msg: M) -> Result<()>;
    fn pre_handle_message(&mut self, msg: &M) -> Result<Transition<M>>;
}
pub struct FSM<M, C>
where
    C: FsmMsgHelper<M>,
{
    state: Box<dyn State<M>>,
    context: C,
}

impl<M, C> FSM<M, C>
where
    C: FsmMsgHelper<M>,
    M: Debug,
{
    pub fn new(state: Box<dyn State<M>>, context: C) -> Self {
        let mut fsm = Self { state, context };
        fsm
    }

    pub fn start(&mut self) -> Result<()> {
        self.state.on_enter(&mut self.context)?;
        Ok(())
    }

    fn state(&self) -> &Box<dyn State<M>> {
        &self.state
    }

    pub fn on_event(&mut self, msg: M) -> Result<()> {
        let state = &mut self.state;
        println!("Calling {}.on_event({:?})", state.name(), msg);
        if let Transition::Abort(AbortReason::User) = self.context.pre_handle_message(&msg)? {
            //TODO: terminate
            Ok(())
        } else {
            log::info!("Calling {}.on_event({:?})", state.name(), msg);

            let t = state.on_event(&mut self.context, msg)?;
            log::info!("Transition :{:?}", t);

            let res = match t {
                Transition::DoNothing => {}
                Transition::ChangeState(new_state) => {
                    state.on_exit(&mut self.context)?;
                    self.state = new_state;
                    self.state.on_enter(&mut self.context)?;
                }
                Transition::Abort(AbortReason::User) => Err(),
                Transition::Abort(AbortReason::Error(e)) => {
                    Err()
                }
            };
            Ok(res)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::fsm::StateName;
    use anyhow::Result;

    use super::{FsmMsgHelper, State, Transition, FSM};

    #[derive(Debug)]
    enum Event {
        Event1,
    }

    struct MsgHelper;
    impl FsmMsgHelper<Event> for MsgHelper {
        fn send_to_self(&mut self, msg: Event) -> Result<()> {
            todo!()
        }

        fn send_to_ui(&mut self, msg: Event) -> Result<()> {
            todo!()
        }

        fn pre_handle_message(&mut self, msg: &Event) -> Result<Transition<Event>> {
            Ok(todo!())
        }
    }

    struct State1;
    impl State<Event> for State1 {}

    #[test]
    fn do_nothing_test() {
        let start_state = State1 {};
        let start_state_name = start_state.name();
        println!("{}", start_state_name);
        let fsm = FSM::new(Box::new(start_state), MsgHelper);
        assert!(fsm.state.name() == start_state_name);
    }
}
