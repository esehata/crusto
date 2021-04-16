// Privacy Enhanced E-mail
trait Pem {
    fn to_pem(&self) -> String;
    fn from_pem(pem: &str);
}