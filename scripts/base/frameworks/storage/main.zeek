##! The storage framework provides a way to store long-term data to disk.

module Storage;

export {
	# Default value for the BackendOptions::forced_sync field.
	const default_forced_sync: bool = F &redef;

	## Base record for backend options that can be passed to
	## :zeek:see:`Storage::Async::open_backend` and
	## :zeek:see:`Storage::Sync::open_backend`. Backend plugins can redef this record
	## to add relevant fields to it.
	type BackendOptions: record {
		## The serializer used for converting Zeek data.
		serializer: Storage::Serializer &default=Storage::STORAGE_SERIALIZER_JSON;

		## Sets the backend into forced-synchronous mode. All operations will run
		## in synchronous mode, even if the async functions are called.  This
		## should generally only be set to ``T`` during testing.
		forced_sync : bool &default=Storage::default_forced_sync;
	};

	## Record for passing arguments to :zeek:see:`Storage::Async::put` and
	## :zeek:see:`Storage::Sync::put`.
	type PutArgs: record {
		## The key to store the value under.
		key: any;

		## The value to store associated with the key.
		value: any;

		## Indicates whether this value should overwrite an existing entry for the
		## key.
		overwrite: bool &default=T;

		## An interval of time until the entry is automatically removed from the
		## backend.
		expire_time: interval &default=0sec;
	};

	# The histogram buckets to use for operation latency metrics, in seconds.
	const latency_metric_bounds: vector of double = { 0.001, 0.01, 0.1, 1.0, } &redef;
}
