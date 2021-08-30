use sp_std::slice::SliceIndex;

pub fn safe_indexing<I>(data: &[u8], idx: I) -> Result<&I::Output, &'static str>
where
    I: SliceIndex<[u8]>,
{
    data.get(idx).ok_or("Index out of bounds")
}

pub fn length_from_raw_data(data: &[u8], offset: &mut usize) -> Result<usize, &'static str> {
    let mut len = *safe_indexing(data, *offset)? as usize;
    if len > 0x80 {
        len = (*safe_indexing(data, *offset + 1)? as usize) * 0x100
            + (*safe_indexing(data, *offset + 2)? as usize);
        *offset += 2;
    }
    Ok(len as usize)
}

#[cfg(test)]
mod test {
    use super::*;
    use frame_support::{assert_err, assert_ok};

    #[test]
    fn index_equal_length_returns_err() {
        // It was discovered a panic occurs if `index == data.len()` due to out of bound
        // indexing. Here the fix is tested.
        //
        // For context see: https://github.com/integritee-network/pallet-teerex/issues/34
        let data: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        assert_err!(safe_indexing(&data, data.len()), "Index out of bounds");
    }

    #[test]
    fn safe_indexing_works() {
        let data: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        assert_eq!(safe_indexing(&data, 1..7), Ok(&data[1..7]));
        assert_eq!(safe_indexing(&data, 3), Ok(&data[3]));
        assert!(safe_indexing(&data, 1..8).is_err());
        assert!(safe_indexing(&data, 6..1).is_err());
        assert!(safe_indexing(&data, 16..19).is_err());
        assert!(safe_indexing(&data, 10).is_err());
    }

    #[test]
    fn start_equals_length_returns_empty_slice() {
        let data: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        assert_ok!(safe_indexing(&data, data.len()..data.len()), &[][..]);
    }
}
