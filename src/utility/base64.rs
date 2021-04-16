pub fn encode(data: &[u8]) -> String {
    let mut s = String::new();

    if data.is_empty() {
        return s;
    }

    let pad_d = (6-(data.len()*8)%6)%6;

    let mut prev=0;

    for (i,x) in data.iter().enumerate() {
        match i%3 {
            0 => {
                s.push(substitute(*x>>2));
            },
            1 => {
                s.push(substitute((prev&0x03)<<4|*x>>4))
            },
            2 => {
                s.push(substitute((prev&0x0F)<<2|*x>>6));
                s.push(substitute(*x&0x3F));
            },
            _ => {},
        }
        prev=*x;
    }

    if pad_d > 0 {
        s.push(substitute(*data.last().unwrap()<<pad_d & 0x3F));
    }

    let pad_s = (4-s.len()%4)%4;

    for _ in 0..pad_s {
        s.push('=');
    }

    s
}

pub fn decode(data: &str) -> Result<Vec<u8>,&'static str> {
    let mut v = Vec::new();

    if data.is_empty() {
        return Ok(v);
    }

    let mut prev=0;

    for (i,c) in data.char_indices() {
        println!("{}",c);
        if c == '=' {
            break;
        }

        let x = inv_substitute(c)?;

        match i%4 {
            0 => {
                prev=x<<2;
            },
            1 => {
                v.push(prev|x>>4);
                prev = (x & 0x0F)<<4;
            },
            2 => {
                v.push(prev|x>>2);
                prev = (x & 0x03)<<6;
            },
            3 => {
                v.push(prev|x);
            },
            _ => {},
        }
    }

    Ok(v)
}

const BASE64_TABLE : [char;64] = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'];

fn substitute(bits: u8) -> char {
    assert!(bits < 64);
    BASE64_TABLE[bits as usize]
}

fn inv_substitute(c: char) -> Result<u8,&'static str> {
    if !(c.is_ascii_alphanumeric() || c=='+' || c=='/') {
        return Err("not a base64 character!");
    }
    
    for (i,x) in BASE64_TABLE.iter().enumerate() {
        if *x==c {
            return Ok(i as u8);
        }
    }

    return Err("logic error"); // unreachable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        println!("{}",encode("ABCDEFG".as_bytes()));
    }

    #[test]
    fn test_decode() {
        println!("{}",String::from_utf8(decode("QUJDREVGw==").unwrap()).unwrap());
    }
}