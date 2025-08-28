#[inline(always)]
pub fn convert_u16_to_two_u8s_be(integer: u16) -> [u8; 2] {
    [(integer >> 8) as u8, integer as u8]
}
#[inline(always)]
pub fn convert_two_u8s_to_u16_be(bytes: [u8; 2]) -> u16 {
    ((bytes[0] as u16) << 8) | bytes[1] as u16
}

pub struct Buffering<'a>(pub &'a mut [u8], pub usize);
impl Buffering<'_> {
    #[inline(always)]
    pub fn write(&mut self, buff: &[u8]) -> &mut Self {
        self.0[self.1..self.1 + buff.len()].copy_from_slice(buff);
        self.1 += buff.len();
        self
    }
    #[inline(always)]
    pub fn get(&self) -> &[u8] {
        &self.0[..self.1]
    }
    #[inline(always)]
    pub fn str(&self) -> Result<&str, std::str::Utf8Error> {
        str::from_utf8(&self.0[..self.1])
    }
    #[inline(always)]
    pub fn mutate(&mut self, indx: usize, value: u8) -> &mut Self {
        self.0[indx] = value;
        self
    }
}

#[inline(always)]
pub fn c_len(http_head: &[u8]) -> usize {
    for line in http_head.split(|&b| b == b'\r' || b == b'\n') {
        if let Some(pos) = line
            .windows(16)
            .position(|window| window.eq_ignore_ascii_case(b"content-length: "))
            && let Ok(length) = std::str::from_utf8(&line[pos + 16..])
                .unwrap_or("0")
                .trim()
                .parse::<usize>()
        {
            return length;
        }
    }
    0
}

#[inline(always)]
pub fn catch_in_buff(find: &[u8], buff: &[u8]) -> Option<(usize, usize)> {
    buff.windows(find.len())
        .position(|pre| pre == find)
        .map(|a| (a, a + find.len()))
}

#[inline(always)]
pub fn parse_range<T: std::str::FromStr>(s: &str) -> Option<std::ops::Range<T>> {
    let mut parts = s.split("-");
    if let (Some(a), Some(b)) = (parts.next(), parts.next())
        && let (Ok(start), Ok(end)) = (a.parse::<T>(), b.parse::<T>())
    {
        return Some(start..end);
    }
    None
}
