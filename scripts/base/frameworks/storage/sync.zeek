##! Synchronous operation methods for the storage framework.

@load ./main

module Storage::Sync;

export {
	## Opens a new backend connection based on a configuration object.
	##
	## btype: A tag indicating what type of backend should be opened. These are
	##        defined by the backend plugins loaded.
	##
	## options: A record containing the configuration for the connection.
	##
	## key_type: The script-level type of keys stored in the backend. Used for
	##           validation of keys passed to other framework methods.
	##
	## val_type: The script-level type of keys stored in the backend. Used for
	##           validation of values passed to :zeek:see:`Storage::Sync::put` as well
	##           as for type conversions for return values from
	##           :zeek:see:`Storage::Sync::get`.
	##
	## Returns: A record containing the status of the operation, and either an error
	##          string on failure or a value on success. The value returned here will
	##          be an ``opaque of BackendHandle``.
	global open_backend: function(btype: Storage::Backend, options: Storage::BackendOptions,
	    key_type: any, val_type: any): Storage::OperationResult;

	## Closes an existing backend connection.
	##
	## backend: A handle to a backend connection.
	##
	## Returns: A record containing the status of the operation and an optional error
	##          string for failures.
	global close_backend: function(backend: opaque of Storage::BackendHandle)
	    : Storage::OperationResult;

	## Inserts a new entry into a backend.
	##
	## backend: A handle to a backend connection.
	##
	## args: A :zeek:see:`Storage::PutArgs` record containing the arguments for the
	##       operation.
	##
	## Returns: A record containing the status of the operation and an optional error
	##          string for failures.
	global put: function(backend: opaque of Storage::BackendHandle,
	    args: Storage::PutArgs): Storage::OperationResult;

	## Gets an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to look up.
	##
	## Returns: A record containing the status of the operation, an optional error
	##          string for failures, and an optional value for success. The value
	##          returned here will be of the type passed into
	##          :zeek:see:`Storage::Sync::open_backend`.
	global get: function(backend: opaque of Storage::BackendHandle, key: any)
	    : Storage::OperationResult;

	## Erases an entry from the backend.
	##
	## backend: A handle to a backend connection.
	##
	## key: The key to erase.
	##
	## Returns: A record containing the status of the operation and an optional error
	##          string for failures.
	global erase: function(backend: opaque of Storage::BackendHandle, key: any)
	    : Storage::OperationResult;
}

function open_backend(btype: Storage::Backend, options: Storage::BackendOptions,
    key_type: any, val_type: any): Storage::OperationResult
	{
	return Storage::Sync::__open_backend(btype, options, key_type, val_type);
	}

function close_backend(backend: opaque of Storage::BackendHandle)
    : Storage::OperationResult
	{
	return Storage::Sync::__close_backend(backend);
	}

function put(backend: opaque of Storage::BackendHandle, args: Storage::PutArgs)
    : Storage::OperationResult
	{
	return Storage::Sync::__put(backend, args$key, args$value, args$overwrite,
	    args$expire_time);
	}

function get(backend: opaque of Storage::BackendHandle, key: any)
    : Storage::OperationResult
	{
	return Storage::Sync::__get(backend, key);
	}

function erase(backend: opaque of Storage::BackendHandle, key: any)
    : Storage::OperationResult
	{
	return Storage::Sync::__erase(backend, key);
	}
