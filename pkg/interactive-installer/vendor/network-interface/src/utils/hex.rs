use std::fmt::Display;

pub(crate) struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    pub(crate) fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }
}

impl<'a> Display for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                write!(f, ":{:02X}", byte)?;
            } else {
                write!(f, "{:02X}", byte)?;
            }
        }
        Ok(())
    }
}
