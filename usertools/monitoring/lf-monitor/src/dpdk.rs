use uds::UnixSeqpacketConn;
use serde_json::Value;


#[derive(Debug)]
pub struct DpdkTelemetry {
    socket_path: String,
    socket: UnixSeqpacketConn,
    dpdk_version: String,
    dpdk_pid: i64,
    max_output_len: i64,
}

impl DpdkTelemetry {
    pub fn new(file_prefix: String) -> Self {
        let runtime_dir: String = get_dpdk_runtime_dir(&file_prefix);
        let socket_path: String = format!("{}/dpdk_telemetry.v2", runtime_dir);

        // Check if socket exists by reading from it
        let socket: UnixSeqpacketConn = UnixSeqpacketConn::connect(socket_path.clone()).unwrap();
        let mut buff: [u8; 16384] = [0u8; 16384];
        socket.recv(&mut buff).unwrap();
        let response: String = String::from_utf8(buff.to_vec()).unwrap();
        // remove trailing null bytes
        let response: String = response.trim_matches(char::from(0)).to_string();
        let dpdk_info: Value = serde_json::from_str(&response).unwrap();

        DpdkTelemetry {
            socket_path: socket_path,
            socket: socket,
            dpdk_version: dpdk_info["version"].to_string(),
            dpdk_pid: dpdk_info["pid"].as_i64().unwrap(),
            max_output_len: dpdk_info["max_output_len"].as_i64().unwrap(),
        }
    }

    pub fn query(&self, query: &str) -> serde_json::Value {
        self.socket.send(query.as_bytes()).unwrap();

        // XXX: For now, we assume that max buffer length is 16384 (which seems to be the DPDK
        // telementry default).
        let mut buff: [u8; 16384] = [0u8; 16384];
        let mut result: String = String::from("");
        loop {
            let n: usize = self.socket.recv(&mut buff).unwrap();
            if n == 0 {
                break;
            }
            let string_result = std::str::from_utf8(&buff[..n]).unwrap();
            result.push_str(string_result);

            // XXX: In case the buffer is not long enough, we might have to call recv again.
            // However, I was not able to implement this behavior.
            break;
        }

        // Parse JSON response
        let v: Value = serde_json::from_str(&result).unwrap();
        return v;
    }
}

impl Drop for DpdkTelemetry {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

fn get_dpdk_runtime_dir(dpdk_file_prefix: &str) -> String {
    let dpdk_runtime_dir = format!("/var/run/dpdk/{}", dpdk_file_prefix);
    return dpdk_runtime_dir;
}
