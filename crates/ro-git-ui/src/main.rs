#![forbid(unsafe_code)]

use ro_git_ui::App;

fn main() {
    yew::Renderer::<App>::new().render();
}
