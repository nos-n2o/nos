//! `nos-tacacs-stub --listen 0.0.0.0:49 --key K --user name:password:role ...`
//! The e2e lab's TACACS+ server.

use nos_tacacs::StubUser;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (mut listen, mut key, mut users) = ("0.0.0.0:49".to_string(), String::new(), vec![]);
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_default();
        match flag.as_str() {
            "--listen" => listen = value,
            "--key" => key = value,
            "--user" => {
                let mut p = value.splitn(3, ':');
                if let (Some(name), Some(password), Some(role)) = (p.next(), p.next(), p.next()) {
                    users.push(StubUser {
                        name: name.into(),
                        password: password.into(),
                        role: role.into(),
                    });
                }
            }
            other => {
                eprintln!("unknown flag {other}");
                std::process::exit(2);
            }
        }
    }
    let addr = listen.parse().expect("--listen is host:port");
    nos_tacacs::serve_stub(addr, &key, users).await
}
