// prevents panics in case of index out of bounds
pub fn safe_indexing(data: &[u8], start: usize, end: usize) -> Result<&[u8], &'static str> {
    if start > end {
        return Err("Illegal indexing");
    }
    if data.len() < end {
        return Err("Index out of bounds");
    }
    Ok(&data[start..end])
}

pub fn safe_indexing_one(data: &[u8], idx: usize) -> Result<u8, &'static str> {
    if data.len() <= idx {
        return Err("Index out of bounds");
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

#[cfg(test)]
mod test {
    use super::*;
    use frame_support::{assert_err, assert_ok};

    #[test]
    fn safe_indexing_works() {
        let data: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        assert_eq!(safe_indexing(&data, 1, 7), Ok(&data[1..7]));
        assert_eq!(safe_indexing_one(&data, 3), Ok(3));
        assert!(safe_indexing(&data, 1, 8).is_err());
        assert!(safe_indexing(&data, 6, 1).is_err());
        assert!(safe_indexing(&data, 16, 19).is_err());
    }

    #[test]
    fn index_equal_length_returns_err() {
        // Todo add security audit context
        let data: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        assert_err!(safe_indexing_one(&data, data.len()), "Index out of bounds");
    }

    #[test]
    fn start_equals_length_returns_empty_slice() {
        // Todo add security audit context
        let data: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        assert_ok!(safe_indexing(&data, data.len(), data.len()), &[][..]);
    }
}
