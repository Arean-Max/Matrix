pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "length overflow".to_string())?;
        if end > self.buf.len() {
            return Err("truncated structure".to_string());
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub(crate) fn sized(&mut self, max: usize) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(format!("field of {n} bytes exceeds limit"));
        }
        self.take(n)
    }

    pub(crate) fn finish(&self) -> Result<(), String> {
        if self.pos != self.buf.len() {
            return Err("trailing bytes".to_string());
        }
        Ok(())
    }
}
