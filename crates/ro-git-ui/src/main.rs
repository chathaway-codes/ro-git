use ro_git_proto::format_clone_command;
use yew::prelude::*;

#[function_component(App)]
pub fn app() -> Html {
    let sample_clone = format_clone_command("localhost", None, "users", "alice", "public", "demo");

    html! {
        <main class="ro-git-app">
            <header>
                <h1>{ "ro-git" }</h1>
                <p>{ "Read-Only Git Repository Index" }</p>
            </header>
            <section data-sample-clone={sample_clone}>
                <p>{ "Select or filter a repository to copy its SSH clone URL." }</p>
            </section>
        </main>
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
