// prevents panics in case of index out of bounds
pub fn safe_indexing(data: &[u8], start: usize, end: usize) -> Result<&[u8], &'static str> {
    if start > end {
        return Err("Illegal indexing");
    }
    if data.len() < end {
        return Err("Index would be out of bounds");
    }
    Ok(&data[start..end])
}

pub fn safe_indexing_one(data: &[u8], idx: usize) -> Result<u8, &'static str> {
    if data.len() < idx {
        return Err("Index would be out of bounds");
    }
    Ok(data[idx])
}

pub fn length_from_raw_data(data: &[u8], offset: &mut usize) -> Result<usize, &'static str> {
    let mut len = safe_indexing_one(data, *offset)? as usize;
    if len > 0x80 {
        len = (safe_indexing_one(data, *offset + 1)? as usize) * 0x100
            + (safe_indexing_one(data, *offset + 2)? as usize);
        *offset += 2;
    }
    Ok(len)
}
