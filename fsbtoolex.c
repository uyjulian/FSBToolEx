
// This is a quick and dirty program to wrap FSBTool to avoid transcoding Vorbis files…

// Based on oggvorbis2fsb5
// Based on decoder_example.c from the Vorbis library

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#else
#include <unistd.h>
#include <libgen.h>
#define _ftprintf fprintf
#define _tcscmp strcmp
#define _tcsncpy strncpy
#define _tfopen fopen
#define _TCHAR char
#define _tmain main
#define _tcsncat strncat
#define _tcslen strlen
#define TEXT(x) x
extern char **environ;
#endif

#if 0
#define dbg_printf(formatX, ...) _ftprintf(stderr, TEXT(formatX), __VA_ARGS__)
#else
#define dbg_printf(formatX, ...)
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <vorbis/codec.h>
#include <tomcrypt.h>

static uint32_t crc32_for_byte(uint32_t r) {
	for(int j = 0; j < 8; ++j)
		r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
	return r ^ (uint32_t)0xFF000000L;
}

static void crc32(const void *data, size_t n_bytes, uint32_t* crc) {
	static uint32_t table[0x100];
	if(!*table)
		for(size_t i = 0; i < 0x100; ++i)
			table[i] = crc32_for_byte(i);
	for(size_t i = 0; i < n_bytes; ++i)
		*crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

typedef struct __attribute__((__packed__)) {
	uint32_t header;
	uint32_t version;
	uint32_t num_samples;
	uint32_t sample_header_size;
	uint32_t name_table_size;
	uint32_t data_size;
	uint32_t mode;
	uint8_t zero[8];
	uint8_t compat_hash[8];
	uint8_t hash[16];
} fsb5_header;

typedef struct __attribute__((__packed__)) {
	uint64_t extra_param : 1;
	uint64_t frequency : 4;
	uint64_t stereo : 1;
	uint64_t data_offset : 28;
	uint64_t samples : 30;
} fsb5_sample_header;

typedef struct __attribute__((__packed__)) {
	uint32_t has_next : 1;
	uint32_t size : 24;
	uint32_t chunk_type : 7;
} fsb5_sample_extra_header;

typedef struct __attribute__((__packed__)) {
	uint8_t channels;
} fsb5_sample_extra_channels_header;

typedef struct __attribute__((__packed__)) {
	uint32_t frequency;
} fsb5_sample_extra_frequency_header;

typedef struct __attribute__((__packed__)) {
	uint32_t loop_start;
	uint32_t loop_end;
} fsb5_sample_extra_loop_header;

typedef struct __attribute__((__packed__)) {
	uint32_t crc32;
	uint32_t position_offset_table_length;
} fsb5_sample_extra_vorbis_header;

typedef struct __attribute__((__packed__)) {
	uint32_t granulepos;
	uint32_t offset;
} fsb5_sample_extra_vorbis_entry_header;

typedef struct __attribute__((__packed__)) linked_list_for_ogg_packets_struct {
	unsigned char *packet;
	long bytes;
	ogg_int64_t granulepos;
	struct linked_list_for_ogg_packets_struct *next;
} linked_list_for_ogg_packets;

int fsb_tool_wrap(int argc, _TCHAR** argv)
{
#ifdef _WIN32
	_TCHAR* modnamebuf = malloc(sizeof(_TCHAR) * 32768);
	_TCHAR* modpathbuf = malloc(sizeof(_TCHAR) * 32768);
	if (modnamebuf && modpathbuf)
	{
		DWORD ret_len = GetModuleFileName(NULL, modnamebuf, 32768);
		if (ret_len)
		{
			DWORD ret_len2 = GetFullPathName(modnamebuf, 32768, modpathbuf, NULL);
			if (ret_len2)
			{
				LPWSTR lpszFileSpec = modpathbuf;
				LPWSTR lpszFileSpecX = modpathbuf;

				if(lpszFileSpecX)
				{
				 if (*lpszFileSpecX == TEXT('\\') || *lpszFileSpecX == TEXT('/'))
				   lpszFileSpec = ++lpszFileSpecX;
				 if (*lpszFileSpecX == TEXT('\\') || *lpszFileSpecX == TEXT('/'))
				   lpszFileSpec = ++lpszFileSpecX;

				 while (*lpszFileSpecX)
				 {
				   if(*lpszFileSpecX == TEXT('\\') || *lpszFileSpecX == TEXT('/'))
				     lpszFileSpec = lpszFileSpecX;
				   else if(*lpszFileSpecX == TEXT(':'))
				   {
				     lpszFileSpec = ++lpszFileSpecX;
				     if (*lpszFileSpecX == TEXT('\\') || *lpszFileSpecX == TEXT('/'))
				       lpszFileSpec++;
				   }
				   lpszFileSpecX++;
				 }

				 if (*lpszFileSpec)
				 {
				   *lpszFileSpec = TEXT('\0');
				 }
				}

				_tcsncat(modpathbuf, TEXT("/FSBTool_original.exe"), 32768);
				STARTUPINFO si;
				PROCESS_INFORMATION pi;
				memset(&si, 0, sizeof(si));
				memset(&pi, 0, sizeof(pi));
				si.cb = sizeof(si);
				dbg_printf("Creating process %ls.\n", GetCommandLine());
				if (CreateProcess(modpathbuf, GetCommandLine(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) == FALSE)
				{
					dbg_printf("Could not create FSBTool_original.exe process at %ls. %d\n", modpathbuf, GetLastError());
					return 3;
				}
			    WaitForSingleObject(pi.hProcess, INFINITE);

			    DWORD exitcode;
			    GetExitCodeProcess(pi.hProcess, &exitcode);

			    CloseHandle(pi.hProcess);
			    CloseHandle(pi.hThread);

			    TerminateProcess(GetCurrentProcess(), exitcode);
			}
			else
			{
				dbg_printf("Could not get full path name.%s", "\n");
			}
		}
		else
		{
			dbg_printf("Could not get module path name.%s", "\n");
		}
		//free(modnamebuf);
		//free(modpathbuf);
	}
#else
	char *modpathbuf;
	modpathbuf = malloc(32768);
	strncpy(modpathbuf, dirname(argv[0]), 32768);
	strncat(modpathbuf, "/FSBTool_original", 32768);
	char **newargv;
	newargv = malloc(sizeof(char*) * argc);
	memcpy(newargv, argv, argc);
	newargv[0] = modpathbuf;
	execve(modpathbuf, newargv, environ);
	dbg_printf("execve FSBTool_original failed.%s", "\n");
#endif
	return 1;
}

int get_sli_loop_points(uint32_t *loop_sample_start, uint32_t *loop_sample_end, char *str)
{
	char *endptr, *foundptr;
	long loop_start = -1;
	long loop_length = -1;
	long loop_to = -1;
	long loop_from = -1;

    if ((foundptr = strstr(str,"LoopStart=")) != NULL && isdigit(foundptr[10])) {
        loop_start = strtol(foundptr+10,&endptr,10);
    }
    if ((foundptr = strstr(str,"LoopLength=")) != NULL && isdigit(foundptr[11])) {
        loop_length = strtol(foundptr+11,&endptr,10);
    }

    if ((foundptr = strstr(str,"To=")) != NULL && isdigit(foundptr[3])) {
        loop_to = strtol(foundptr+3,&endptr,10);
    }
    if ((foundptr = strstr(str,"From=")) != NULL && isdigit(foundptr[5])) {
        loop_from = strtol(foundptr+5,&endptr,10);
    }

    if (loop_start >= 0 && loop_length >= 0) {
    	*loop_sample_start = loop_start;
    	*loop_sample_end = loop_start + loop_length;
    	return 1;
    }
    else if (loop_from >= 0 && loop_to >= 0) {
    	*loop_sample_start = loop_to;
    	*loop_sample_end = loop_from;
    	return 1;
    }

	return 0;
}

#include <fcntl.h>

int _tmain(int argc, _TCHAR** argv) {
	ogg_sync_state oy;   /* sync and verify incoming physical bitstream */
	ogg_stream_state os; /* take physical pages, weld into a logical stream of packets */
	ogg_page og;         /* one Ogg bitstream page. Vorbis packets are inside */
	ogg_packet op;       /* one raw packet of data for decode */

	vorbis_info vi;      /* struct that stores all the static vorbis bitstream settings */
	vorbis_comment vc;   /* struct that stores all the bitstream user comments */
	vorbis_dsp_state vd; /* central working state for the packet->PCM decoder */
	vorbis_block vb;     /* local working space for packet->PCM decode */

	uint32_t setup_packet_crc32;

	fsb5_header fh;
	fsb5_sample_header fsh;
	fsb5_sample_extra_header fseh_channels;
	fsb5_sample_extra_channels_header fsech;
	fsb5_sample_extra_header fseh_frequency;
	fsb5_sample_extra_frequency_header fsefh;
	fsb5_sample_extra_header fseh_loop;
	fsb5_sample_extra_loop_header fselh;
	fsb5_sample_extra_header fseh_vorbisdata;
	fsb5_sample_extra_vorbis_header fsevh;
	fsb5_sample_extra_vorbis_entry_header *fseveh;

	linked_list_for_ogg_packets *ll;
	linked_list_for_ogg_packets *ll_last;
	linked_list_for_ogg_packets *ll_current;

	char *buffer;
	int bytes;

	_TCHAR *inputfile;
	_TCHAR *outputfile;
	_TCHAR *outputformat;

	hash_state md;


	/********** Decode setup ************/

	memset(&oy, 0, sizeof(oy));
	memset(&os, 0, sizeof(os));
	memset(&og, 0, sizeof(og));
	memset(&op, 0, sizeof(op));
	memset(&vi, 0, sizeof(vi));
	memset(&vc, 0, sizeof(vc));
	memset(&vd, 0, sizeof(vd));
	memset(&vb, 0, sizeof(vb));

	setup_packet_crc32 = 0;
	ll = NULL;
	ll_last = NULL;
	ll_current = NULL;

	inputfile = NULL;
	outputfile = NULL;
	outputformat = TEXT("fsb");
	for (int i = 1; i < argc; i += 1)
	{
		if (!_tcscmp(argv[i], TEXT("-i")) && i + 1 < argc)
		{
			i += 1;
			inputfile = argv[i];
		}
		else if (!_tcscmp(argv[i], TEXT("-o")) && i + 1 < argc)
		{
			i += 1;
			outputfile = argv[i];
		}
		else if (!_tcscmp(argv[i], TEXT("-l")) && i + 1 < argc)
		{
			i += 1;
			// we don't need library path; skip
		}
		else if (!_tcscmp(argv[i], TEXT("-h")) && i + 1 < argc)
		{
			i += 1;
			// we don't need cache path; skip
		}
		else if (!_tcscmp(argv[i], TEXT("-c")) && i + 1 < argc)
		{
			i += 1;
			// we don't need compression format; skip
		}
		else if (!_tcscmp(argv[i], TEXT("-C")) && i + 1 < argc)
		{
			i += 1;
			outputformat = argv[i];
		}
		else if (!_tcscmp(argv[i], TEXT("-q")) && i + 1 < argc)
		{
			i += 1;
			// we don't need quality; skip
		}
		else if (!_tcscmp(argv[i], TEXT("-s")) && i + 1 < argc)
		{
			i += 1;
			// we don't need sample rate; skip
		}
	}

	if (!inputfile || !outputfile || !outputformat || _tcscmp(outputformat, TEXT("fsb")))
	{
		dbg_printf("Input or output file not specified.%s", "\n");
		return fsb_tool_wrap(argc, argv);
	}

	ogg_sync_init(&oy); /* Now we can read pages */

	FILE *infile = _tfopen(inputfile, TEXT("rb"));
	if (!infile)
	{
		dbg_printf("Error: could not open input file%s", "\n");
		return 1;
	}

	while (1) { /* we repeat if the bitstream is chained */
		int eos = 0;
		int i;

		/* grab some data at the head of the stream. We want the first page
			 (which is guaranteed to be small and only contain the Vorbis
			 stream initial header) We need the first page to get the stream
			 serialno. */

		/* submit a 4k block to libvorbis' Ogg layer */
		buffer = ogg_sync_buffer(&oy, 4096);
		bytes = fread(buffer, 1, 4096, infile);
		ogg_sync_wrote(&oy, bytes);

		/* Get the first page. */
		if (ogg_sync_pageout(&oy, &og) != 1) {
			/* have we simply run out of data?  If so, we're done. */
			if (bytes < 4096)
				break;

			/* error case.  Must not be Vorbis data */
			dbg_printf("Input does not appear to be an Ogg bitstream.%s", "\n");
			return fsb_tool_wrap(argc, argv);
		}

		/* Get the serial number and set up the rest of decode. */
		/* serialno first; use it to set up a logical stream */
		ogg_stream_init(&os, ogg_page_serialno(&og));

		/* extract the initial header from the first page and verify that the Ogg bitstream is in fact Vorbis data */

		/* I handle the initial header first instead of just having the code
			 read all three Vorbis headers at once because reading the initial
			 header is an easy way to identify a Vorbis bitstream and it's
			 useful to see that functionality seperated out. */

		vorbis_info_init(&vi);
		vorbis_comment_init(&vc);
		if (ogg_stream_pagein(&os, &og) < 0) {
			/* error; stream version mismatch perhaps */
			dbg_printf("Error reading first page of Ogg bitstream data.%s", "\n");
			return fsb_tool_wrap(argc, argv);
		}

		if (ogg_stream_packetout(&os, &op) != 1) {
			/* no page? must not be vorbis */
			dbg_printf("Error reading initial header packet.%s", "\n");
			return fsb_tool_wrap(argc, argv);
		}

		if (vorbis_synthesis_headerin(&vi, &vc, &op) < 0) {
			/* error case; not a vorbis header */
			dbg_printf("This Ogg bitstream does not contain Vorbis audio data.%s", "\n");
			return fsb_tool_wrap(argc, argv);
		}

		/* At this point, we're sure we're Vorbis. We've set up the logical
			 (Ogg) bitstream decoder. Get the comment and codebook headers and
			 set up the Vorbis decoder */

		/* The next two packets in order are the comment and codebook headers.
			 They're likely large and may span multiple pages. Thus we read
			 and submit data until we get our two packets, watching that no
			 pages are missing. If a page is missing, error out; losing a
			 header page is the only place where missing data is fatal. */

		i = 0;
		while (i < 2) {
			while (i < 2) {
				int result = ogg_sync_pageout(&oy, &og);
				if (result == 0)
					break; /* Need more data */
				/* Don't complain about missing or corrupt data yet. We'll catch it at the packet output phase */
				if (result == 1) {
					ogg_stream_pagein(&os, &og); /* we can ignore any errors here as they'll also become apparent at packetout */
					while (i < 2) {
						result = ogg_stream_packetout(&os, &op);
						if (result == 0)
							break;
						if (result < 0) {
							/* Uh oh; data at some point was corrupted or missing! We can't tolerate that in a header.  Die. */
							dbg_printf("Corrupt secondary header.  Exiting.%s", "\n");
							return 1;
						}
						result = vorbis_synthesis_headerin(&vi, &vc, &op);
						if (result < 0) {
							dbg_printf("Corrupt secondary header.  Exiting.%s", "\n");
							return 1;
						}
						i++;
						if (i == 2)
						{
							setup_packet_crc32 = 0;
							crc32(op.packet, op.bytes, &setup_packet_crc32);
						}
					}
				}
			}
			/* no harm in not checking before adding more */
			buffer = ogg_sync_buffer(&oy, 4096);
			bytes = fread(buffer, 1, 4096, infile);
			if (bytes == 0 && i < 2) {
				dbg_printf("End of file before finding all Vorbis headers!%s", "\n");
				return 1;
			}
			ogg_sync_wrote(&oy, bytes);
		}

		/* Throw the comments plus a few lines about the bitstream we're decoding */
		{
			char **ptr = vc.user_comments;
			while (*ptr) {
				dbg_printf("%s\n", *ptr);
				++ptr;
			}
			dbg_printf("\nBitstream is %d channel, %ldHz\n", vi.channels,
							vi.rate);
			dbg_printf("Encoded by: %s\n\n", vc.vendor);
		}

		/* OK, got and parsed all three headers. Initialize the Vorbis packet->PCM decoder. */
		if (vorbis_synthesis_init(&vd, &vi) == 0) { /* central decode state */
			/* local state for most of the decode so multiple block decodes can proceed in parallel. */
			/* We could init multiple vorbis_block structures for vd here */
			vorbis_block_init(&vd, &vb);

			/* The rest is just a straight decode loop until end of stream */
			while (!eos) {
				while (!eos) {
					int result = ogg_sync_pageout(&oy, &og);
					if (result == 0)
						break;          /* need more data */
					if (result < 0) { /* missing or corrupt data at this page position */
						dbg_printf("Corrupt or missing data in bitstream; continuing...%s", "\n");
					} else {
						ogg_stream_pagein(&os, &og); /* can safely ignore errors at this point */
						while (1) {
							result = ogg_stream_packetout(&os, &op);

							if (result == 0)
								break; /* need more data */
							if (result < 0) { /* missing or corrupt data at this page position */
								/* no reason to complain; already complained above */
							} else {
								/* we have a packet.  Decode it */
								ll_current = malloc(sizeof(linked_list_for_ogg_packets));
								memset(ll_current, 0, sizeof(linked_list_for_ogg_packets));
								ll_current->packet = malloc(op.bytes);
								memcpy(ll_current->packet, op.packet, op.bytes);
								ll_current->bytes = op.bytes;
								ll_current->granulepos = op.granulepos;
								if (!ll)
								{
									ll = ll_current;
								}
								else
								{
									ll_last->next = ll_current;
								}
								ll_last = ll_current;
							}
						}
						if (ogg_page_eos(&og))
							eos = 1;
					}
				}
				if (!eos) {
					buffer = ogg_sync_buffer(&oy, 4096);
					bytes = fread(buffer, 1, 4096, infile);
					ogg_sync_wrote(&oy, bytes);
					if (bytes == 0)
						eos = 1;
				}
			}

			/* ogg_page and ogg_packet structs always point to storage in libvorbis.  They're never freed or manipulated directly */

			vorbis_block_clear(&vb);
			vorbis_dsp_clear(&vd);
		} else {
			dbg_printf("Error: Corrupt header during playback initialization.%s", "\n");
		}

		/* clean up this logical bitstream; before exit we see if we're followed by another [chained] */

		ogg_stream_clear(&os);
		vorbis_comment_clear(&vc);
#if 0
		// We need the frequency and channel information. Don't clear
		vorbis_info_clear(&vi); /* must be called last */
#endif
	}

	/* OK, clean up the framer */
	ogg_sync_clear(&oy);

	FILE *outfile = _tfopen(outputfile, TEXT("wb"));
	if (!outfile)
	{
		dbg_printf("Error: could not open output file%s", "\n");
		return 1;
	}
	md5_init(&md);
	int fsb_header_size = 0;
	int fsb_sample_header_size = 0;
	int packet_count = 0;
	int total_data_size = 0;
	ll_current = ll;
	while (ll_current != NULL)
	{
		if (ll_current->granulepos != -1)
		{
			packet_count += 1;
		}
		total_data_size += sizeof(uint16_t);
		total_data_size += ll_current->bytes;
		ll_current = ll_current->next;
	}
	int total_data_padding = 32 - (total_data_size % 32);
	memset(&fh, 0, sizeof(fh));
	fh.header = 0x35425346;
	fh.version = 1;
	fh.num_samples = 1;
	fh.name_table_size = 0;
	fh.data_size = total_data_size + total_data_padding;
	fh.mode = 15; // Vorbis
	fh.zero[0] = 1; // Unknown what this does…
	// fh.hash is md5 hash of heaedr
	fsb_header_size += sizeof(fh);
	fsh.extra_param = 1;
	switch (vi.rate)
	{
		case 48000:
		{
			fsh.frequency = 9;
			break;
		}
		case 44100:
		{
			fsh.frequency = 8;
			break;
		}
		case 32000:
		{
			fsh.frequency = 7;
			break;
		}
		case 24000:
		{
			fsh.frequency = 6;
			break;
		}
		case 22050:
		{
			fsh.frequency = 5;
			break;
		}
		case 16000:
		{
			fsh.frequency = 4;
			break;
		}
		case 11025:
		{
			fsh.frequency = 3;
			break;
		}
		case 11000:
		{
			fsh.frequency = 2;
			break;
		}
		case 8000:
		{
			fsh.frequency = 1;
			break;
		}
		default:
		{
			fsh.frequency = 0;
			break;
		}
	}
	switch (vi.channels)
	{
		case 2:
		{
			fsh.stereo = 1;
			break;
		}
		case 1:
		{
			fsh.stereo = 0;
			break;
		}
		default:
		{
			fsh.stereo = 0;
			break;
		}
	}
	fsh.samples = 0;
	fsb_sample_header_size += sizeof(fsh);
	memset(&fseh_channels, 0, sizeof(fseh_channels));
	if (vi.channels != 2 && vi.channels != 1)
	{
		fseh_channels.has_next = 1;
		fseh_channels.size = sizeof(fsech);
		fseh_channels.chunk_type = 1; // channels
		fsech.channels = vi.channels;
		fsb_sample_header_size += sizeof(fseh_channels) + fseh_channels.size;
	}
	memset(&fseh_frequency, 0, sizeof(fseh_frequency));
	if (fsh.frequency == 0)
	{
		fseh_frequency.has_next = 1;
		fseh_frequency.size = sizeof(fsefh);
		fseh_frequency.chunk_type = 2; // frequency
		fsefh.frequency = vi.rate;
		fsb_sample_header_size += sizeof(fseh_frequency) + fseh_frequency.size;
	}
	memset(&fseh_loop, 0, sizeof(fseh_loop));
	_TCHAR * infile_sli_path = malloc((_tcslen(inputfile) + 7) * sizeof(_TCHAR));
	memset(infile_sli_path, 0, (_tcslen(inputfile) + 7) * sizeof(_TCHAR));
	_tcsncpy(infile_sli_path, inputfile, (_tcslen(inputfile) + 7) * sizeof(_TCHAR));
	_tcsncat(infile_sli_path, TEXT(".sli"), (_tcslen(inputfile) + 7) * sizeof(_TCHAR));
	FILE *infile_sli = _tfopen(infile_sli_path, TEXT("rb"));
	if (infile_sli)
	{
		fseek(infile_sli, 0, SEEK_END);
		long fsize = ftell(infile_sli);
		fseek(infile_sli, 0, SEEK_SET);

		char *infile_sli_contents = malloc(fsize + 5);
		fread(infile_sli_contents, 1, fsize, infile_sli);
		infile_sli_contents[fsize] = 0;
		//fclose(infile_sli);

		
		uint32_t loop_sample_start = 0;
		uint32_t loop_sample_end = 0;
		if (get_sli_loop_points(&loop_sample_start, &loop_sample_end, infile_sli_contents))
		{
			dbg_printf("Found loop point %" PRIu32 "-%" PRIu32 ".\n", loop_sample_start, loop_sample_end);
			fseh_loop.has_next = 1;
			fseh_loop.size = sizeof(fselh);
			fseh_loop.chunk_type = 3; // loop
			fselh.loop_start = loop_sample_start;
			fselh.loop_end = loop_sample_end;
			fsb_sample_header_size += sizeof(fseh_loop) + fseh_loop.size;
		}
		else
		{
			dbg_printf("Could not find loop points.%s", "\n");
		}
		//free(infile_sli_contents);
	}
	else
	{
		dbg_printf(".sli file not found; not adding loop points.%s", "\n");
	}
	//free(infile_sli_path);
	memset(&fseh_vorbisdata, 0, sizeof(fseh_vorbisdata));
	fseh_vorbisdata.has_next = 0;
	fseh_vorbisdata.size = sizeof(fsevh) + sizeof(fsb5_sample_extra_vorbis_entry_header) * packet_count;
	fseh_vorbisdata.chunk_type = 11; // vorbis data
	fsevh.crc32 = setup_packet_crc32;
	fsevh.position_offset_table_length = sizeof(fsb5_sample_extra_vorbis_entry_header) * packet_count;
	fsb_sample_header_size += sizeof(fseh_vorbisdata) + fseh_vorbisdata.size;
	int data_padding = 16 - ((fsb_header_size + fsb_sample_header_size) % 16);
	fsb_sample_header_size += data_padding;
	fh.sample_header_size = fsb_sample_header_size;
	fsb_header_size += fsb_sample_header_size;
	
	fseveh = malloc(sizeof(fsb5_sample_extra_vorbis_entry_header) * packet_count * 2); // Multiply by 2 for extra insurance
	packet_count = 0;
	ll_current = ll;
	int total_offset = 0;
	fsh.data_offset = 0;
	int max_granulepos = 0;
	while (ll_current != NULL)
	{
		if (ll_current->granulepos != -1)
		{
			fseveh[packet_count].offset = total_offset;
			fseveh[packet_count].granulepos = ll_current->granulepos;
			if (max_granulepos < ll_current->granulepos)
			{
				max_granulepos = ll_current->granulepos;
			}
			packet_count += 1;
		}
		total_offset += sizeof(uint16_t) + ll_current->bytes;
		ll_current = ll_current->next;
	}
	fsh.samples = max_granulepos;
	md5_process(&md, (unsigned char *)&fsh, sizeof(fsh));
	if (fseh_channels.has_next)
	{
		md5_process(&md, (unsigned char *)&fseh_channels, sizeof(fseh_channels));
		md5_process(&md, (unsigned char *)&fsech, sizeof(fsech));
	}
	if (fseh_frequency.has_next)
	{
		md5_process(&md, (unsigned char *)&fseh_frequency, sizeof(fseh_frequency));
		md5_process(&md, (unsigned char *)&fsefh, sizeof(fsefh));
	}
	if (fseh_loop.has_next)
	{
		md5_process(&md, (unsigned char *)&fseh_loop, sizeof(fseh_loop));
		md5_process(&md, (unsigned char *)&fselh, sizeof(fselh));
	}
	md5_process(&md, (unsigned char *)&fseh_vorbisdata, sizeof(fseh_vorbisdata));
	md5_process(&md, (unsigned char *)&fsevh, sizeof(fsevh));
	md5_process(&md, (unsigned char *)fseveh, sizeof(fsb5_sample_extra_vorbis_entry_header) * packet_count);
	md5_process(&md, (unsigned char *)&fh, sizeof(fh)); // The 60 byte main header gets hashed last
	md5_done(&md, fh.hash);
	fwrite(&fh, 1, sizeof(fh), outfile);
	fwrite(&fsh, 1, sizeof(fsh), outfile);
	if (fseh_channels.has_next)
	{
		fwrite(&fseh_channels, 1, sizeof(fseh_channels), outfile);
		fwrite(&fsech, 1, sizeof(fsech), outfile);
	}
	if (fseh_frequency.has_next)
	{
		fwrite(&fseh_frequency, 1, sizeof(fseh_frequency), outfile);
		fwrite(&fsefh, 1, sizeof(fsefh), outfile);
	}
	if (fseh_loop.has_next)
	{
		fwrite(&fseh_loop, 1, sizeof(fseh_loop), outfile);
		fwrite(&fselh, 1, sizeof(fselh), outfile);
	}
	fwrite(&fseh_vorbisdata, 1, sizeof(fseh_vorbisdata), outfile);
	fwrite(&fsevh, 1, sizeof(fsevh), outfile);
	fwrite(fseveh, 1, sizeof(fsb5_sample_extra_vorbis_entry_header) * packet_count, outfile);
	uint8_t data_padding_arr[32];
	memset(data_padding_arr, 0, sizeof(data_padding_arr));
	fwrite(data_padding_arr, 1, data_padding, outfile);
	ll_current = ll;
	while (ll_current != NULL)
	{
		uint16_t packet_length;
		packet_length = ll_current->bytes;
		fwrite(&packet_length, 1, sizeof(packet_length), outfile);
		if (ll_current->bytes)
		{
			fwrite(ll_current->packet, 1, ll_current->bytes, outfile);
		}
		ll_current = ll_current->next;
	}
	fwrite(data_padding_arr, 1, total_data_padding, outfile);
	fclose(outfile);

	dbg_printf("Done.%s", "\n");
	return (0);
}
