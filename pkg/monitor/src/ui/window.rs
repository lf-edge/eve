// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::events;
use crate::model::model::Model;
use crate::ui::widgets::input_field::InputFieldElement;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::{fmt::Debug, rc::Rc};

use crossterm::event::KeyEvent;
use indexmap::IndexMap;
use log::{debug, trace};
use ratatui::layout::Rect;

use crate::traits::{IEventHandler, IPresenter, IVisible, IWidget, IWindow, TextInput};
use anyhow::Result;

use super::{
    action::{Action, UiActions},
    focus_tracker::{FocusMode, FocusTracker},
};

pub type WidgetMap = IndexMap<String, Box<dyn IWidget>>;
pub type LayoutMap = HashMap<String, Rect>;

pub type LayoutFn<D> = Rc<dyn Fn(&mut Window<D>, &Rect, &Rc<Model>)>;
pub type RenderFn<D> = Rc<dyn Fn(&mut Window<D>, &Rect, &mut ratatui::Frame<'_>, &Rc<Model>)>;
pub type ChildActionFn<D> = Rc<dyn Fn(&mut Window<D>, &String, &UiActions) -> Option<Action>>;

pub struct WindowBuilder<D> {
    name: String,
    widgets: WidgetMap,
    // callback for layout
    do_layout: Option<LayoutFn<D>>,
    // callback for rendering
    do_render: Option<RenderFn<D>>,
    // taborder
    tab_order: Option<Vec<String>>,
    // initial focus
    focused_view: Option<String>,

    on_child_ui_action: Option<ChildActionFn<D>>,
    on_init: Option<Rc<dyn Fn(&mut Window<D>)>>,

    on_key_event: Option<Rc<dyn Fn(&mut Window<D>, KeyEvent) -> Option<Action>>>,

    state: Option<D>,
}

impl<D> WindowBuilder<D> {
    pub fn widget<S: Into<String>>(mut self, name: S, widget: impl IWidget + 'static) -> Self {
        self.widgets.insert(name.into(), Box::new(widget));
        self
    }

    pub fn with_layout<F>(mut self, do_layout: F) -> Self
    where
        F: Fn(&mut Window<D>, &Rect, &Rc<Model>) + 'static,
    {
        self.do_layout = Some(Rc::new(do_layout));
        self
    }

    pub fn with_render<F>(mut self, do_render: F) -> Self
    where
        F: Fn(&mut Window<D>, &Rect, &mut ratatui::Frame<'_>, &Rc<Model>) + 'static,
    {
        self.do_render = Some(Rc::new(do_render));
        self
    }

    pub fn with_on_child_ui_action<F>(mut self, on_child_ui_action: F) -> Self
    where
        F: Fn(&mut Window<D>, &String, &UiActions) -> Option<Action> + 'static,
    {
        self.on_child_ui_action = Some(Rc::new(on_child_ui_action));
        self
    }

    pub fn with_on_key_event<F>(mut self, on_key_event: F) -> Self
    where
        F: Fn(&mut Window<D>, KeyEvent) -> Option<Action> + 'static,
    {
        self.on_key_event = Some(Rc::new(on_key_event));
        self
    }

    pub fn with_on_init<F>(mut self, on_init: F) -> Self
    where
        F: Fn(&mut Window<D>) + 'static,
    {
        self.on_init = Some(Rc::new(on_init));
        self
    }

    #[allow(dead_code)]
    pub fn with_taborder(mut self, tab_order: Vec<String>) -> Self {
        self.tab_order = Some(tab_order);
        self
    }

    #[allow(dead_code)]
    pub fn with_focused_view<S: Into<String>>(mut self, name: S) -> Self {
        self.focused_view = Some(name.into());
        self
    }

    pub fn with_state(mut self, state: D) -> Self {
        self.state = Some(state);
        self
    }

    pub fn build(self) -> Result<Window<D>> {
        // focused view if set must exist in widgets and taborder if provided
        if let Some(focused_view) = &self.focused_view {
            if !self.widgets.contains_key(focused_view) {
                return Err(anyhow::anyhow!(
                    "Focused view not found in widgets: {}",
                    focused_view
                ));
            }
            if let Some(order) = &self.tab_order {
                if !order.contains(focused_view) {
                    return Err(anyhow::anyhow!(
                        "Focused view not found in tab order: {}",
                        focused_view
                    ));
                }
            }
        }

        let ft = if let Some(order) = self.tab_order {
            let tab_order = order
                .clone()
                .into_iter()
                .filter(|name| self.widgets.get(name).is_some_and(|f| f.can_focus()))
                .collect();
            FocusTracker::create_from_taborder(tab_order, self.focused_view, FocusMode::Wrap)
        } else {
            FocusTracker::create_from_views(&self.widgets, self.focused_view, FocusMode::Wrap)
        };

        Ok(Window::new(
            &self.name,
            ft,
            self.widgets,
            self.do_layout,
            self.do_render,
            self.on_child_ui_action,
            self.on_key_event,
            self.on_init,
            self.state.unwrap(),
        ))
    }
}

pub struct Window<D> {
    pub name: String,
    ft: FocusTracker,
    widgets: WidgetMap,
    layout: LayoutMap,
    do_layout: Option<LayoutFn<D>>,
    do_render: Option<RenderFn<D>>,
    on_init: Option<Rc<dyn Fn(&mut Window<D>)>>,
    on_child_ui_action: Option<ChildActionFn<D>>,
    on_key_event: Option<Rc<dyn Fn(&mut Window<D>, KeyEvent) -> Option<Action>>>,
    on_init_called: bool,
    pub state: D,
}

impl<S> Debug for Window<S> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

impl<D> Window<D> {
    pub(self) fn new<S: Into<String>>(
        name: S,
        ft: FocusTracker,
        widgets: WidgetMap,
        do_layout: Option<LayoutFn<D>>,
        do_render: Option<RenderFn<D>>,
        on_child_ui_action: Option<ChildActionFn<D>>,
        on_key_event: Option<Rc<dyn Fn(&mut Window<D>, KeyEvent) -> Option<Action>>>,
        on_init: Option<Rc<dyn Fn(&mut Window<D>)>>,
        state: D,
    ) -> Self {
        Self {
            name: name.into(),
            ft,
            widgets,
            layout: HashMap::new(),
            do_layout,
            do_render,
            on_child_ui_action,
            on_key_event,
            state,
            on_init,
            on_init_called: false,
        }
    }

    pub fn builder<S: Into<String>>(name: S) -> WindowBuilder<D> {
        WindowBuilder {
            name: name.into(),
            widgets: WidgetMap::new(),
            do_layout: None,
            do_render: None,
            tab_order: None,
            focused_view: None,
            on_child_ui_action: None,
            on_key_event: None,
            state: None,
            on_init: None,
        }
    }

    pub fn add_widget<S: Into<String>>(&mut self, name: S, widget: impl IWidget + 'static) {
        self.widgets.insert(name.into(), Box::new(widget));
    }

    pub fn get_widget_mut<S: Into<String>>(&mut self, name: S) -> Option<&mut Box<dyn IWidget>> {
        self.widgets.get_mut(&name.into())
    }

    pub fn get_widget<S: Into<String>>(&self, name: S) -> Option<&Box<dyn IWidget>> {
        self.widgets.get(&name.into())
    }

    pub fn update_layout<S: Into<String>>(&mut self, name: S, rect: Rect) {
        self.layout.insert(name.into(), rect);
    }

    pub fn clear_layout(&mut self) {
        self.layout.clear();
    }

    pub fn get_layout<S: Into<String>>(&mut self, name: S) -> Rect {
        self.layout.get(&name.into()).unwrap().clone()
    }

    pub fn render_widget<S: Into<String>>(&mut self, name: S, frame: &mut ratatui::Frame<'_>) {
        let name = name.into();
        let focused = self.ft.get_focused_view().unwrap_or_default() == name;
        let rect = self.layout.get(&name).unwrap().clone();
        let widget = self.widgets.get_mut(&name).unwrap();
        widget.render(&rect, frame, focused);
    }

    pub fn handle_key_event_override(&mut self, key: KeyEvent) -> Option<Action> {
        let on_key_event = self.on_key_event.clone()?;
        let action = on_key_event(self, key)?;
        Some(action)
    }

    pub fn handle_key_event_in_focus_tracker(&mut self, key: KeyEvent) -> Option<Action> {
        let action = self.ft.handle_key_event(key)?;
        Some(Action::new(self.name.clone(), action))
    }

    pub fn handle_key_event_in_focused_view(&mut self, key: KeyEvent) -> Option<Action> {
        let focused_view = self.ft.get_focused_view()?;
        let widget = self.widgets.get_mut(&focused_view)?;
        let action = widget.handle_key_event(key)?;
        Some(Action::new(focused_view, action))
    }

    pub fn handle_child_ui_action(&mut self, action: Action) -> Option<Action> {
        let on_child_ui_action = self.on_child_ui_action.clone()?;
        let action = on_child_ui_action(self, &action.source, &action.action)?;
        Some(action.source(self.name.clone()))
    }

    pub fn get_focused_view(&self) -> usize {
        self.ft.get_focused_index()
    }

    pub(crate) fn set_focused_view(&mut self, focus_tracker_state: usize) {
        self.ft.set_focused_index(focus_tracker_state);
    }

    pub fn set_focus_tracker_tab_order<S: Into<String>>(&mut self, tab_order: Vec<S>) {
        let tab_order: Vec<String> = tab_order.into_iter().map(|s| s.into()).collect();
        self.ft.set_tab_order(tab_order);
    }

    pub fn text_input_mut(&mut self, id: &str) -> Option<&mut dyn TextInput> {
        self.widgets.get_mut(id)?.as_input_field_mut()
    }
}

impl<D> IWindow for Window<D> {
    fn status_bar_tips(&self) -> Option<String> {
        // get the focused widget
        self.ft.get_focused_view().and_then(|focused_widget| {
            self.widgets.get(&focused_widget).and_then(|widget| {
                // check if the widget has a status bar tip
                widget.tips_in_focus()
            })
        })
    }
}

impl<D> IEventHandler for Window<D> {
    fn handle_event(&mut self, event: events::Event) -> Option<Action> {
        match event {
            events::Event::Key(key) => {
                // there are 2 possuble cases when handling key events:
                // 1. the key event is handled by the window and returns an activity
                // 2. the key event is not handled by the window and returns None. It must be handled by further processing

                let next_action = self.handle_key_event_in_focus_tracker(key);

                if next_action.is_some() {
                    debug!(
                        "handle_event: key event handled by focus tracker. action: {:?}",
                        next_action
                    );
                    // TODO: it doesn't make sense to return action here since it is just a Redraw
                    return next_action;
                }

                // check if the window overrides the key event handler
                // window may have custom handling for some widgets e.g. TabWidget
                let next_action = self.handle_key_event_override(key);

                if let Some(next_action) = next_action {
                    debug!(
                        "handle_event: key event handled by window. action: {:?}",
                        next_action
                    );
                    match &next_action.action {
                        ui_action => {
                            if let Some(on_child_action) = self.on_child_ui_action.clone() {
                                (on_child_action)(self, &next_action.source, ui_action).and_then(
                                    |new_action| Some(new_action.source(self.name.clone())),
                                );
                            }
                            return Some(next_action);
                        }
                    }
                }

                // forward the event to the focused view
                let next_action = self.handle_key_event_in_focused_view(key)?;

                debug!(
                    "handle_event: key event handled by focused view. action: {:?}",
                    next_action
                );

                match next_action.action {
                    ref ui_action => {
                        if let Some(on_child_action) = self.on_child_ui_action.clone() {
                            let next_action =
                                (on_child_action)(self, &next_action.source, &ui_action).and_then(
                                    |new_action| Some(new_action.source(self.name.clone())),
                                );
                            return next_action;
                        }
                        return Some(next_action);
                    }
                }
            }
            events::Event::Tick => {
                // forward to all widgets
                self.widgets.iter_mut().for_each(
                    |(_, widget)| {
                        if let Some(_activity) = widget.handle_tick() {}
                    },
                );
                return Some(Action::new(self.name.clone(), UiActions::Redraw));
            }
            _ => {}
        }
        None
    }
}

impl<D> IVisible for Window<D> {}
impl<D> IPresenter for Window<D> {
    fn render(
        &mut self,
        area: &Rect,
        frame: &mut ratatui::Frame<'_>,
        model: &Rc<Model>,
        focused: bool,
    ) {
        // print layout map
        trace!("Layout: {:#?}", self.layout);

        // call on_init if it is the first time
        if !self.on_init_called {
            self.on_init_called = true;
            if let Some(on_init) = self.on_init.clone() {
                (on_init)(self);
            }
        }

        let focused_widget = self.ft.get_focused_view().unwrap_or_default();

        // always do layout first. New widgets and layout entries may appear
        if let Some(layouter) = self.do_layout.borrow_mut() {
            let layouter = layouter.clone();
            (layouter)(self, area, &model);
        }

        // do custom rendering before we render widgets
        if let Some(custom_render) = self.do_render.borrow_mut() {
            let custom_render = custom_render.clone();
            (custom_render)(self, area, frame, &model)
        };

        let layout = &self.layout;

        self.widgets
            .iter_mut()
            .filter_map(|(name, widget)| {
                layout
                    .get(name)
                    .inspect(|f| trace!("Layout for {}: {:#?}", name, f))
                    .map(|r| (r, widget, *name == focused_widget))
            })
            .for_each(|(rect, widget, w_focused)| {
                widget.render(rect, frame, w_focused && focused);
            });
    }

    fn can_focus(&self) -> bool {
        true
    }
}
