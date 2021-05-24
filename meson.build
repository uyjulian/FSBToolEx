project(
	'fsbtoolex',
	[
		'c',
	],
	default_options: [
		'optimization=3',
		'debug=true',
		'warning_level=1'
	],
	version: 'unknown'
)

fsbtoolex_cflags = []

fsbtoolex_ldflags = []
if target_machine.system() == 'windows'
	fsbtoolex_cflags += [
		'-DUNICODE',
		'-D_UNICODE',
	]
	fsbtoolex_ldflags += [
		'-static',
		'-municode',
	]
endif
if target_machine.system() == 'linux'
	fsbtoolex_ldflags += [
		'-lm',
	]
endif

fsbtoolex_src = [
	'fsbtoolex.c',
	'external/libtomcrypt/src/hashes/md5.c',
	'external/libtomcrypt/src/misc/compare_testvector.c',
	'external/libtomcrypt/src/misc/crypt/crypt_argchk.c',
	'external/ogg/src/bitwise.c',
	'external/ogg/src/framing.c',
	'external/vorbis/lib/bitrate.c',
	'external/vorbis/lib/block.c',
	'external/vorbis/lib/codebook.c',
	'external/vorbis/lib/envelope.c',
	'external/vorbis/lib/floor0.c',
	'external/vorbis/lib/floor1.c',
	'external/vorbis/lib/info.c',
	'external/vorbis/lib/lpc.c',
	'external/vorbis/lib/lsp.c',
	'external/vorbis/lib/mapping0.c',
	'external/vorbis/lib/mdct.c',
	'external/vorbis/lib/psy.c',
	'external/vorbis/lib/registry.c',
	'external/vorbis/lib/res0.c',
	'external/vorbis/lib/sharedbook.c',
	'external/vorbis/lib/smallft.c',
	'external/vorbis/lib/synthesis.c',
	'external/vorbis/lib/vorbisfile.c',
	'external/vorbis/lib/window.c',
]

fsbtoolex_includes = [
	'include',
	'external/libtomcrypt/src/headers',
	'external/ogg/include',
	'external/vorbis/include',
]

executable(
	'FSBToolEx',
	sources: fsbtoolex_src,
	c_args: fsbtoolex_cflags,
	link_args: fsbtoolex_ldflags,
	include_directories: include_directories(fsbtoolex_includes),
)
