# Add CRC checksum and version information to ELF and binary files

Embedded programmers often face the task to insert a checksum into binaries
after linking. A bootloader can then verify the checksum before allowing a
firmware update or running the program.

add_version_info is a small python script that can insert version control
information and checksums into ELF or binary firmware images.


## Usage

The tool will search for two 16 byte markers in the firmware image, and fill
in a structure with the current git or subversion id, a checksum, and build
time information. The checksum is forged, so that running a CRC32 check over
the entire image will yield the requested checksum.


## Example

#### `version.h`

```C
#include <stdint.h>

#define VCS_INFO_START "VCSINFO2_START->"
#define VCS_INFO_END   "<---VCSINFO2_END"

struct version_info {
    char        vcs_info_start[16];

    // set by add-version-info.py
    //
    uint32_t    image_crc;
    uint32_t    image_start;
    uint32_t    image_size;

    char        vcs_id[32];
    char        build_user[16];
    char        build_host[16];
    char        build_date[16];
    char        build_time[16];

    // set at compile-time
    //
    char        product_name[32];
    int         major;
    int         minor;
    int         patch;

    char        vcs_info_end[16];
};

extern volatile const struct version_info  version_info;

void print_version_info(int verbose);
```

#### `version.c`

```C

#include "version.h"

volatile const struct version_info version_info = {
    .vcs_info_start = VCS_INFO_START,
    .product_name   = "add_version_info example",
    .major          = 1,
    .minor          = 2,
    .patch          = 3,
    .vcs_info_end   = VCS_INFO_END
};

void print_version_info(const struct version_info *v)
{
    printf(
        "%s v%d.%d.%d %s %s %s\n"
        "  Compiled %s %s by %s on %s\n"
        v->product_name,
        v->major, v->minor, v->patch,
        v->vcs_id,
        v->build_date, v->build_time,
        v->build_date, v->build_time,
        v->build_user, v->build_host
    );
}

void main(void)
{
    print_version_info(&version_info);
}

```

#### `Makefile` rule

```Makefile

# Link: create ELF output file from object files
#
$(TARGET).elf: $(OBJECTS)
	@echo
	@echo Linking: $@
	$(CC) $(OBJECTS) $(LDFLAGS) --output $(basename $@).tmp

	@echo
	@echo Post-processing: $@
	add-version-info.py -v $(basename $@).tmp $@

```
