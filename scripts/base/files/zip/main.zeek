module ZIP;

export {
	type File: record {
		## True if from global directory header, false if from local file header
		global_: bool;
		## File ID associated with content analysis of this file. Only available for local
		## headers where file content has been further processed.
		fid: string &optional;
		## Name of file
		filename: string;
		## Timestamp of file
		time_: time;
		## Comment associated with file.
		comment: string;
		## Compression type
		compression: ZIP::CompressionMethod;
		## True if encrypted
		encrypted: bool;
	};
}

# Take the filename as reported from ZIP::file() and
# attach if to the file.
#
# Note that **f** is the file object of the ZIP archive,
# not the file object of the ZIP::File, so we go via Files::lookup_file()
# to the the file object.
event ZIP::file(f: fa_file, meta: ZIP::File)
	{
	if ( meta$global_ || ! meta?$fid )
		return;

	# ZIP::file() after file_new(), so this should work out.
	local fid = meta$fid;
	if ( ! Files::file_exists(fid) )
		return;

	local meta_f = Files::lookup_file(meta$fid);

	# Also, the default file_new() handler should've attached $info.
	if ( ! meta_f?$info )
		return;

	meta_f$info$filename = meta$filename;
	}
