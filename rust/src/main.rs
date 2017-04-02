extern crate regex;

use std::io;
use regex::Regex;

fn main() {
   println!("Packet Analyzer - Rust version");

   let mut line = String::new();

//   let mut result = 
   let mut result = io::stdin().read_line(&mut line);//
println!("{}", line);
result.expect("Error");

   let mut end = false;
   while !end {
   	 line = String::new();
   	 result = io::stdin().read_line(&mut line);
    match result {
      Ok(0) => end = true,
      Ok(n) => end = false,
      Err(e) => end = true      
    }
    print!("{}", line);
    analyze(line);
}
   
println!("END");
   

// todo : stdin read, end on eof
}

// lines of form \s+0xDDDD: hex... to byte representation
fn analyze(line: String) {
   //let re = Regex::new(r"^\s*0x[0-9a-fA-H]{4}:\s+([0-9a-fA-H]\s+)\s*$").unwrap();
   //let re = Regex::new(r"^\s*0x([0-9a-fA-H]{4}):.*\s*$").unwrap();
   let re = Regex::new(r"^\s*0x([0-9a-fA-H]{4}):\s+([0-9a-fA-F]+\s+)+\s*$").unwrap();
   if(re.is_match(line.as_str()))
   {
	println!("MATCH");
   	for c in re.captures_iter(line.as_str()) {
	    println!("{}; {} - {}", &c[1], c.len(),&c[2]);
	    
       }
   }
}