#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod actions;
mod api;
mod keys;
mod state;
mod views;

pub async fn sleep_ms(ms: u32) {
    #[cfg(target_arch = "wasm32")]
    {
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .expect("window")
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32)
                .expect("set_timeout");
        });
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ms;
    }
}

fn main() {
    dioxus::launch(views::App);
}
