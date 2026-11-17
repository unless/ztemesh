#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "controller-1905.h"
#include "controller-peer.h"
#include "controller-steer.h"

#define PEERS_KNOWN 32
#define BSS_STATIONS_SUFFIX ".sta"

/* The vendor's glibc 2.26 on ARM32 exports only the versioned stat entry points, as controller-service.c notes for
 * its own reads; a host build, which is where the peer codec test runs, has the plain fstat(). */
#if defined(__arm__)
extern int __fxstat(int, int, struct stat *);
#define fstat(fd, info) __fxstat(3, (fd), (info))
#endif

static const char *peers_dir(void)
{
    const char *dir = getenv("ZTE_MESH_PEERS_DIR");
    return dir && *dir ? dir : "/run/zte-mesh/peers";
}

/* One path under the peers directory, through a temporary name in the same directory and then renamed, so the
 * service never reads a half value. `name` is "<MAC>.<kind>", or "<MAC>.<BSSID>.sta" for one BSS of one node.
 * 1 = the file is in place. */
static int write_named(const char *name, const char *text, size_t bytes)
{
    char path[256], temp[264];
    int fd;
    if (snprintf(path, sizeof(path), "%s/%s", peers_dir(), name) >= (int)sizeof(path) ||
        snprintf(temp, sizeof(temp), "%s.t", path) >= (int)sizeof(temp))
        return 0;
    fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0)
        return 0;
    {
        ssize_t written = write(fd, text, bytes);
        int closed = close(fd);
        if (written == (ssize_t)bytes && !closed && !rename(temp, path))
            return 1;
    }
    (void)unlink(temp);
    return 0;
}

/* "<MAC>.<kind>": one file per (node, thing the page shows). 1 = the file is in place. */
static int write_peer(const uint8_t *mac, const char *kind, const char *text, size_t bytes)
{
    char name[48];
    if (snprintf(name, sizeof(name), "%02x:%02x:%02x:%02x:%02x:%02x.%s",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], kind) >= (int)sizeof(name))
        return 0;
    return write_named(name, text, bytes);
}

/* "<MAC>.<BSSID>.sta": how many stations the node counted on that BSS, one number per frame that reported it.
 * The count of a BSS with nobody associated is a zero, and a zero written here is the node saying so - which is
 * why a frame that names a BSS at all is enough, and why the reader tells "no entry" from "entry: 0". */
static int write_bss(const uint8_t *mac, const struct ap_bss_metric *bss)
{
    char name[64], text[24];
    int n;
    if (snprintf(name, sizeof(name),
                 "%02x:%02x:%02x:%02x:%02x:%02x.%02x:%02x:%02x:%02x:%02x:%02x" BSS_STATIONS_SUFFIX,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 bss->bssid[0], bss->bssid[1], bss->bssid[2], bss->bssid[3], bss->bssid[4], bss->bssid[5])
        >= (int)sizeof(name))
        return 0;
    n = snprintf(text, sizeof(text), "%u\n", bss->stations);
    return n > 0 && write_named(name, text, (size_t)n);
}

/* An SSID as it can sit on a tab-separated line: control bytes (a newline would start a new row, a tab would
 * shift the columns) become spaces. The child sanitizes before sending; this side sanitizes again because the
 * frame is the other router's, not this one's. */
static void assoc_ssid(char out[CONTROLLER_SSID_MAX + 1], const char *text)
{
    size_t k;
    for (k = 0; k < CONTROLLER_SSID_MAX && text[k]; k++) {
        unsigned char c = (unsigned char)text[k];
        out[k] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
    }
    out[k] = 0;
}

/* "<MAC>.assoc": the clients a node reports as associated to its own APs, one per line:
 *
 *   epoch=<unix>
 *   <station> <TAB> <BSSID> <TAB> <SSID>
 *
 * The stamp is this side's clock, the moment the report arrived: "has this node told us lately" is a question
 * about the reader's own clock, and clock skew between the two routers must not decide whether a device shows.
 * The whole file is rewritten per report, so a client that left is gone from the next; a report with no client
 * writes the stamp alone, which is the node saying "nobody is on my APs" rather than "no answer". */
static int write_assoc(const uint8_t *mac, const struct ap_client_group *groups, unsigned int group_count,
                       const uint8_t macs[][6], unsigned int mac_count)
{
    char text[2300], ssid[CONTROLLER_SSID_MAX + 1];
    size_t used;
    unsigned int k, j;
    int n = snprintf(text, sizeof(text), "epoch=%ld\n", (long)time(NULL));
    if (n <= 0)
        return 0;
    used = (size_t)n;
    for (k = 0; k < group_count; k++) {
        assoc_ssid(ssid, groups[k].ssid);
        for (j = 0; j < groups[k].count && groups[k].first + j < mac_count; j++) {
            const uint8_t *station = macs[groups[k].first + j];
            n = snprintf(text + used, sizeof(text) - used,
                         "%02x:%02x:%02x:%02x:%02x:%02x\t"
                         "%02x:%02x:%02x:%02x:%02x:%02x\t%s\n",
                         station[0], station[1], station[2], station[3], station[4], station[5],
                         groups[k].bssid[0], groups[k].bssid[1], groups[k].bssid[2],
                         groups[k].bssid[3], groups[k].bssid[4], groups[k].bssid[5], ssid);
            if (n <= 0 || (size_t)n >= sizeof(text) - used)
                return 0;
            used += (size_t)n;
        }
    }
    return write_peer(mac, "assoc", text, used);
}

/* -----------------------------------------------------------------------------------------------
 * Factory children (G100S / G1612) never send this repository's client sub-TLV 0x70. They do answer
 * every STA Metrics Query (0x800d) with a STA Metrics Response (0x800e), whose TLV 0x96 is
 * <STA MAC[6], 0x01, BSSID[6], metrics...>; the Ethernet source is the child's AL MAC. One frame
 * names one station, while <node>.assoc is a whole table, so observations are cached here and the
 * file is rewritten atomically on every report. The 30-second window matches the reader's ASSOC_AGE.
 * ----------------------------------------------------------------------------------------------- */

#define ASSOC_CACHE_MAX 96
#define ASSOC_BSS_MAX 64
#define ASSOC_AGE 30

struct assoc_observation {
    uint8_t node[6];
    uint8_t station[6];
    uint8_t bssid[6];
    time_t seen;
};

struct assoc_bss_name {
    uint8_t node[6];
    uint8_t bssid[6];
    char ssid[CONTROLLER_SSID_MAX + 1];
};

static struct assoc_observation assoc_cache[ASSOC_CACHE_MAX];
static unsigned int assoc_cache_count;
static struct assoc_bss_name assoc_bss_names[ASSOC_BSS_MAX];
static unsigned int assoc_bss_count;

/* SSID bytes off the wire are not NUL-terminated and may carry control characters that would break
 * the tab-separated .assoc rows. */
static void assoc_copy_ssid(char out[CONTROLLER_SSID_MAX + 1], const uint8_t *text, size_t length)
{
    size_t k;
    if (length > CONTROLLER_SSID_MAX)
        length = CONTROLLER_SSID_MAX;
    for (k = 0; k < length; k++) {
        unsigned char c = text[k];
        out[k] = (c < 0x20 || c == 0x7f) ? ' ' : (char)c;
    }
    out[k] = 0;
}

/* AP Operational BSS (0x83): radio count, then per radio {radio id[6], interface count}, then per
 * interface {BSSID[6], SSID length, SSID}. The same walk node_metrics_decode() counts on; here the
 * advertised names are kept so a client's BSSID can be shown with its real SSID. */
static void assoc_learn_bss(const uint8_t *node, const uint8_t *value, size_t length)
{
    unsigned int radios, r;
    size_t at = 0;
    if (length < 1)
        return;
    radios = value[at++];
    for (r = 0; r < radios; r++) {
        unsigned int interfaces, i;
        if (length - at < 7)
            return;
        at += 6; /* radio identifier */
        interfaces = value[at++];
        for (i = 0; i < interfaces; i++) {
            const uint8_t *bssid;
            size_t ssid;
            unsigned int k;
            struct assoc_bss_name *slot = NULL;
            if (length - at < 7)
                return;
            bssid = value + at;
            at += 6;
            ssid = value[at++];
            if (ssid > length - at)
                return;
            for (k = 0; k < assoc_bss_count; k++)
                if (!memcmp(assoc_bss_names[k].node, node, 6) &&
                    !memcmp(assoc_bss_names[k].bssid, bssid, 6)) {
                    slot = &assoc_bss_names[k];
                    break;
                }
            if (!slot && assoc_bss_count < ASSOC_BSS_MAX)
                slot = &assoc_bss_names[assoc_bss_count++];
            if (slot) {
                memcpy(slot->node, node, 6);
                memcpy(slot->bssid, bssid, 6);
                assoc_copy_ssid(slot->ssid, value + at, ssid);
            }
            at += ssid;
        }
    }
}

static const char *assoc_ssid_for(const uint8_t *node, const uint8_t *bssid)
{
    unsigned int k;
    for (k = 0; k < assoc_bss_count; k++)
        if (!memcmp(assoc_bss_names[k].node, node, 6) && !memcmp(assoc_bss_names[k].bssid, bssid, 6))
            return assoc_bss_names[k].ssid;
    return "";
}

/* The service publishes the on-air names and the node topology in the run directory the sandbox
 * shares with the host (peers/ lives there too). Reading them here keeps the .so self-contained:
 * no UCI call, no shell helper, no second daemon. ZTE_MESH_RUN_DIR is the host test's handle on it. */
static const char *assoc_run_dir(void)
{
    const char *dir = getenv("ZTE_MESH_RUN_DIR");
    return dir && *dir ? dir : "/run/zte-mesh";
}

static void assoc_trim(char *text)
{
    size_t n = strlen(text);
    while (n && (text[n - 1] == '\n' || text[n - 1] == '\r' || text[n - 1] == ' '))
        text[--n] = 0;
}

/* /run/zte-mesh/config is written by the init script from the validated UCI values: the two names
 * are the ones actually on the air, including the dual-band-sync / suffix derivation. */
static void assoc_read_profile(char s0[CONTROLLER_SSID_MAX + 1], char s1[CONTROLLER_SSID_MAX + 1])
{
    char path[256], line[256], suffix[16] = "-5G";
    FILE *f;
    int sync = 0;
    s0[0] = s1[0] = 0;
    if (snprintf(path, sizeof(path), "%s/config", assoc_run_dir()) >= (int)sizeof(path))
        return;
    f = fopen(path, "r");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        char *value;
        if (!eq)
            continue;
        *eq = 0;
        value = eq + 1;
        assoc_trim(value);
        if (!strcmp(line, "radio0.ssid"))
            assoc_copy_ssid(s0, (const uint8_t *)value, strlen(value));
        else if (!strcmp(line, "radio1.ssid"))
            assoc_copy_ssid(s1, (const uint8_t *)value, strlen(value));
        else if (!strcmp(line, "wifi.dual_band_sync"))
            sync = (value[0] == '1') ? 1 : 0;
        else if (!strcmp(line, "wifi.essid_suffix")) {
            size_t n = strlen(value);
            if (n > sizeof(suffix) - 1)
                n = sizeof(suffix) - 1;
            memcpy(suffix, value, n);
            suffix[n] = 0;
        }
    }
    fclose(f);
    if (sync) {
        memcpy(s1, s0, strlen(s0) + 1);
    } else if (!s1[0] && s0[0]) {
        snprintf(s1, CONTROLLER_SSID_MAX + 1, "%s%s", s0, suffix);
        s1[CONTROLLER_SSID_MAX] = 0;
    }
}

/* A hand-rolled MAC reader rather than sscanf/strtol: glibc 2.38+ redirects those to
 * __isoc23_sscanf / __isoc23_strtol, which the device's glibc 2.26 does not export. */
static int assoc_hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int assoc_parse_mac(const char *text, uint8_t out[6])
{
    unsigned int k;
    if (strlen(text) < 17)
        return 0;
    for (k = 0; k < 6; k++) {
        int hi = assoc_hex((unsigned char)text[3 * k]);
        int lo = assoc_hex((unsigned char)text[3 * k + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        if (k < 5 && text[3 * k + 2] != ':')
            return 0;
        out[k] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static void assoc_set_name(const uint8_t *node, const uint8_t *bssid, const char *ssid)
{
    unsigned int k;
    struct assoc_bss_name *slot = NULL;
    size_t n;
    for (k = 0; k < assoc_bss_count; k++)
        if (!memcmp(assoc_bss_names[k].node, node, 6) && !memcmp(assoc_bss_names[k].bssid, bssid, 6)) {
            slot = &assoc_bss_names[k];
            break;
        }
    if (!slot && assoc_bss_count < ASSOC_BSS_MAX)
        slot = &assoc_bss_names[assoc_bss_count++];
    if (!slot)
        return;
    memcpy(slot->node, node, 6);
    memcpy(slot->bssid, bssid, 6);
    n = strlen(ssid);
    if (n > CONTROLLER_SSID_MAX)
        n = CONTROLLER_SSID_MAX;
    memcpy(slot->ssid, ssid, n);
    slot->ssid[n] = 0;
}

/* state.json lists each node's BSSes in radio order. The first is 2.4 GHz, the second 5 GHz, and
 * anything after that a guest or a hidden backhaul with no name to show. A cheap ordered scan is
 * enough: the file is the service's own, not arbitrary user input. */
static void assoc_load_state(const char *s0, const char *s1)
{
    static char buf[16384];
    char path[256];
    FILE *f;
    size_t n;
    char *p;
    if (snprintf(path, sizeof(path), "%s/state.json", assoc_run_dir()) >= (int)sizeof(path))
        return;
    f = fopen(path, "r");
    if (!f)
        return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    p = buf;
    while ((p = strstr(p, "\"mac\":\"")) != NULL) {
        uint8_t node[6];
        char *next = strstr(p + 7, "\"mac\":\"");
        char *limit = next ? next : buf + n;
        char *r = p + 7;
        unsigned int idx = 0;
        int ok = assoc_parse_mac(p + 7, node);
        while ((r = strstr(r, "\"bssid\":\"")) != NULL) {
            uint8_t bssid[6];
            if (r >= limit)
                break;
            if (ok && assoc_parse_mac(r + 9, bssid)) {
                idx++;
                assoc_set_name(node, bssid, idx == 1 ? s0 : (idx == 2 ? s1 : ""));
            }
            r += 9;
        }
        p = limit;
        if (!next)
            break;
    }
}

static void assoc_refresh_names(time_t now)
{
    static time_t loaded;
    char s0[CONTROLLER_SSID_MAX + 1], s1[CONTROLLER_SSID_MAX + 1];
    if (loaded && now >= loaded && now - loaded < 5)
        return;
    assoc_read_profile(s0, s1);
    assoc_load_state(s0, s1);
    loaded = now;
}

static int assoc_remember(const uint8_t *node, const uint8_t *station, const uint8_t *bssid, time_t now)
{
    unsigned int k, oldest = 0;
    struct assoc_observation *slot = NULL;
    for (k = 0; k < assoc_cache_count; k++) {
        if (!memcmp(assoc_cache[k].node, node, 6) && !memcmp(assoc_cache[k].station, station, 6)) {
            slot = &assoc_cache[k];
            break;
        }
        if (assoc_cache[k].seen < assoc_cache[oldest].seen)
            oldest = k;
    }
    if (!slot) {
        if (assoc_cache_count < ASSOC_CACHE_MAX)
            slot = &assoc_cache[assoc_cache_count++];
        else
            slot = &assoc_cache[oldest];
    }
    memcpy(slot->node, node, 6);
    memcpy(slot->station, station, 6);
    memcpy(slot->bssid, bssid, 6);
    slot->seen = now;
    return 1;
}

static void assoc_rewrite_node(const uint8_t *node, time_t now)
{
    char text[4096];
    size_t used;
    unsigned int k;
    int n = snprintf(text, sizeof(text), "epoch=%ld\n", (long)now);
    if (n <= 0)
        return;
    used = (size_t)n;
    for (k = 0; k < assoc_cache_count; k++) {
        const struct assoc_observation *o = &assoc_cache[k];
        if (memcmp(o->node, node, 6) || o->seen > now || now - o->seen > ASSOC_AGE)
            continue;
        n = snprintf(text + used, sizeof(text) - used,
                     "%02x:%02x:%02x:%02x:%02x:%02x\t"
                     "%02x:%02x:%02x:%02x:%02x:%02x\t%s\n",
                     o->station[0], o->station[1], o->station[2], o->station[3], o->station[4], o->station[5],
                     o->bssid[0], o->bssid[1], o->bssid[2], o->bssid[3], o->bssid[4], o->bssid[5],
                     assoc_ssid_for(node, o->bssid));
        if (n <= 0 || (size_t)n >= sizeof(text) - used)
            break;
        used += (size_t)n;
    }
    (void)write_peer(node, "assoc", text, used);
}

/* Re-stamp every node with an observation, not just the one whose frame arrived: the reader drops a
 * file whose epoch is older than 30 seconds, and a quiet node must not disappear while the others
 * keep answering. */
static void assoc_rewrite_all(time_t now)
{
    unsigned int i, k;
    for (i = 0; i < assoc_cache_count; i++) {
        for (k = 0; k < i; k++)
            if (!memcmp(assoc_cache[k].node, assoc_cache[i].node, 6))
                break;
        if (k == i)
            assoc_rewrite_node(assoc_cache[i].node, now);
    }
}

static void assoc_note_frame(const uint8_t *frame, size_t bytes, const struct cmdu_header *header)
{
    struct tlv_cursor cursor;
    const uint8_t *value, *node = frame + 6;
    unsigned int type;
    size_t length;
    time_t now = time(NULL);
    int seen = 0;
    if (header->type == CONTROLLER_MSG_AP_CAPABILITY_REPORT) {
        tlv_open(&cursor, frame, bytes);
        while (tlv_next(&cursor, &type, &value, &length))
            if (type == CONTROLLER_TLV_AP_OPERATIONAL_BSS)
                assoc_learn_bss(node, value, length);
        return;
    }
    if (header->type != CONTROLLER_MSG_STA_METRICS_RESPONSE)
        return;
    tlv_open(&cursor, frame, bytes);
    while (tlv_next(&cursor, &type, &value, &length))
        if (type == CONTROLLER_TLV_STA_METRICS && length >= 13) {
            /* <STA MAC[6]> <0x01> <BSSID[6]> <metrics...>. The middle byte is the one ZTE puts
             * between the two addresses; the trailing metrics are not needed here. */
            assoc_remember(node, value, value + 7, now);
            seen = 1;
        }
    if (seen) {
        assoc_refresh_names(now);
        assoc_rewrite_all(now);
    }
}

/* Is this MAC one of the PEERS_KNOWN the daemon will record? 1 = admitted (a known MAC, or a new one with room
 * left), 0 = the budget is full and this frame is from a stranger. */
static int admit(const uint8_t *mac)
{
    static uint8_t known[PEERS_KNOWN][6];
    static unsigned int count;
    unsigned int k;
    for (k = 0; k < count; k++)
        if (!memcmp(known[k], mac, 6))
            return 1;
    if (count >= PEERS_KNOWN)
        return 0;
    memcpy(known[count++], mac, 6);
    return 1;
}

int controller_peer_note(const uint8_t *frame, size_t bytes)
{
    struct cmdu_header header;
    struct tlv_cursor cursor;
    struct node_metrics metrics;
    struct ap_bss_metric bss_list[CONTROLLER_AP_BSS_MAX];
    const uint8_t *value, *mac = frame + 6;
    unsigned int type, bss_count = 0, k;
    size_t length, used = 0;
    int light = -1, written = 0;
    char text[72];
    char software[CONTROLLER_INVENTORY_TEXT + 1];
    int n;

    if (bytes < CONTROLLER_1905_HEADER || !cmdu_decode(frame, bytes, &header) ||
        !header.last_fragment || header.fragment)
        return 0;

    /* The factory-children client attribution path runs before the early returns below: a 0x800e
     * carries no AP metrics and would otherwise be dropped as status chatter. */
    assoc_note_frame(frame, bytes, &header);

    /* The answers to a client action: a BTM report (0x8015) says whether the client accepted, and a Steering
     * Completed (0x8017) says it left. Both name the client, which is what the action table keys on, so the file is
     * written for the client's MAC and not for the agent that sent the frame. */
    if (header.type == STEER_MSG_BTM_REPORT) {
        struct steer_btm_report report;
        if (!steer_decode_btm_report(frame, bytes, &report))
            return 0;
        if (!admit(report.client))
            return 0;
        n = snprintf(text, sizeof(text), "ok=%d\n", report.status == 0 ? 1 : 0);
        return n > 0 && write_peer(report.client, "btm", text, (size_t)n);
    }
    if (header.type == STEER_MSG_COMPLETED) {
        struct steer_completed done;
        static const char accepted[] = "ok=1\n";
        if (!steer_decode_completed(frame, bytes, &done) || !admit(done.client))
            return 0;
        return write_peer(done.client, "btm", accepted, sizeof(accepted) - 1);
    }

    software[0] = 0;
    tlv_open(&cursor, frame, bytes);
    while (tlv_next(&cursor, &type, &value, &length)) {
        struct zte_cursor zte;
        /* The version only means something inside an AP Capability Report: the factory daemon puts this TLV in
         * that message and reads it back from it, and the number is its own, not the standard's. */
        if (type == CONTROLLER_TLV_DEVICE_INVENTORY) {
            if (header.type == CONTROLLER_MSG_AP_CAPABILITY_REPORT)
                device_inventory_software(value, length, software, sizeof(software));
            continue;
        }
        /* Only a HigherLayerResponse carries the light: the same sub-TLV number inside another message type is a
         * different field, and the master reads it from the response too. */
        if (header.type != 0x000e || type != CONTROLLER_TLV_VENDOR || !zte_vendor_open(&zte, value, length))
            continue;
        while (zte_vendor_next(&zte, &type, &value, &length))
            if (type == 0x21 && length >= 7) {
                light = value[6] ? 1 : 0;
                mac = value; /* the AL MAC the child reports for itself */
            }
    }
    if (!node_metrics_decode(frame, bytes, &metrics))
        return 0;
    /* Only frames that describe the link or its load are worth a file: the daemon's status chatter (CMDU 0x0004 on
     * the lab link, ~2/s) says nothing the page shows, and rewriting a file for it would churn the tmpfs for no
     * gain. */
    if (!(metrics.fields & (NODE_METRIC_STATIONS | NODE_METRIC_BSS)) &&
        header.type != 0x0003 && header.type != 0x0006 && header.type != 0x000e && light < 0 && !software[0])
        return 0;
    if (!admit(mac))
        return 0;
    if (metrics.fields & NODE_METRIC_STATIONS)
        bss_count = ap_metrics_by_bss(frame, bytes, bss_list, CONTROLLER_AP_BSS_MAX);

    /* A version is not a number, and it does not go stale the way a station count does, so it gets its own file
     * with the text in it instead of a key in the metrics digest. */
    if (software[0]) {
        n = snprintf(text, sizeof(text), "%s\n", software);
        if (n > 0 && (size_t)n < sizeof(text))
            written += write_peer(mac, "software", text, (size_t)n);
    }
    if (light >= 0) {
        n = snprintf(text, sizeof(text), "light=%d\n", light);
        if (n > 0)
            written += write_peer(mac, "light", text, (size_t)n);
    }
    /* A count that the frame did not carry is left out, so the reader sees "no data" instead of a zero that looks
     * measured. */
    if (metrics.fields & NODE_METRIC_STATIONS)
        used += (size_t)snprintf(text + used, sizeof(text) - used, "stations=%u\n", metrics.stations);
    if (metrics.fields & NODE_METRIC_BSS)
        used += (size_t)snprintf(text + used, sizeof(text) - used, "bss=%u\n", metrics.bss);
    if (metrics.hops > 0)
        used += (size_t)snprintf(text + used, sizeof(text) - used, "hops=%d\n", metrics.hops);
    if (used)
        written += write_peer(mac, "metrics", text, used);
    /* The same frame counted its stations per BSS; that breakdown is the only way the page can tell a busy 5G
     * from an idle radio with one guest. The digest above stays the frame's own total, so a frame whose list this
     * decoder will not split (a repeated BSSID, more than CONTROLLER_AP_BSS_MAX of them) still leaves a number. */
    for (k = 0; k < bss_count; k++)
        written += write_bss(mac, &bss_list[k]);
    /* The same answer may carry the node's client list (vendor sub-TLV 0x70, see controller-1905.h). A node that
     * does not - a factory child, or a build from before this existed - leaves no file, and the reader then has
     * nothing to attribute, which is the state before this feature. */
    if (header.type == CONTROLLER_MSG_AP_METRICS_RESPONSE) {
        struct ap_client_group groups[CONTROLLER_AP_BSS_MAX];
        uint8_t client_macs[CONTROLLER_CLIENTS_MAX][6];
        int found = ap_clients_decode(frame, bytes, groups, CONTROLLER_AP_BSS_MAX, client_macs,
                                      CONTROLLER_CLIENTS_MAX);
        if (found >= 0) {
            unsigned int clients = found ? groups[found - 1].first + groups[found - 1].count : 0;
            written += write_assoc(mac, groups, (unsigned int)found, client_macs, clients);
        }
    }
    return written;
}

/* The one number in "<dir>/<mac>.<bssid>.sta", or -1: the text this side wrote, checked rather than trusted,
 * because the directory is world-writable tmpfs and a stray file has to read as "no entry". */
static int read_bss_entry(const char *name, time_t *when)
{
    char path[256], text[24];
    struct stat info;
    ssize_t bytes;
    unsigned int value = 0;
    int fd, k;
    if (snprintf(path, sizeof(path), "%s/%s", peers_dir(), name) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 1 || info.st_size >= (off_t)sizeof(text)) {
        (void)close(fd);
        return -1;
    }
    bytes = read(fd, text, sizeof(text) - 1);
    (void)close(fd);
    if (bytes < 1)
        return -1;
    text[bytes] = 0;
    /* One line, the way this side writes it: the end-of-line is not part of the number, and anything else that is
     * not a digit is not a station count either. */
    while (bytes && (text[bytes - 1] == '\n' || text[bytes - 1] == '\r' || text[bytes - 1] == ' '))
        text[--bytes] = 0;
    if (!bytes)
        return -1;
    for (k = 0; text[k]; k++) {
        if (text[k] < '0' || text[k] > '9')
            return -1;
        value = value * 10u + (unsigned int)(text[k] - '0');
        if (value > 0xffffu) /* a u16 is what the wire carries; anything wider is not a station count */
            return -1;
    }
    *when = info.st_mtime;
    return (int)value;
}

/* "<MAC>.<BSSID>.sta": the two MAC halves in their own places, the tail as it is spelled here. Nothing else in the
 * directory is an entry, and a name that only looks like one is what someone else's file would be. */
static int is_bss_entry_name(const char *name, const char *mac)
{
    const size_t bssid = 18; /* strlen("aa:bb:cc:dd:ee:ff.") */
    size_t k;
    if (strlen(name) != 17 + 1 + 17 + (sizeof(BSS_STATIONS_SUFFIX) - 1) || memcmp(name, mac, 17) || name[17] != '.')
        return 0;
    for (k = 0; k < 17; k++) {
        const char c = name[bssid + k];
        if (k % 3 == 2) {
            if (c != ':')
                return 0;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return !memcmp(name + bssid + 17, BSS_STATIONS_SUFFIX, sizeof(BSS_STATIONS_SUFFIX) - 1);
}

/* One live entry into the detail list, kept in BSSID order: readdir() gives the directory's own order, which
 * changes when a file is rewritten, and a page that shows the same rows in a different order every second looks
 * like the network is. A list that is already full drops the largest BSSID - the sum above still counted it. */
static void put_detail(struct peer_bss_load *load, const char *name, unsigned int stations, long age)
{
    struct peer_bss_entry *d = load->detail;
    const char *bssid = name + 18; /* "<mac 17>.<bssid 17>.sta" */
    unsigned int k = load->listed;
    if (k >= CONTROLLER_AP_BSS_MAX) {
        if (strcmp(d[CONTROLLER_AP_BSS_MAX - 1].bssid, bssid) <= 0)
            return;
        k = CONTROLLER_AP_BSS_MAX - 1;
    }
    while (k > 0 && strcmp(d[k - 1].bssid, bssid) > 0) {
        d[k] = d[k - 1];
        k--;
    }
    memcpy(d[k].bssid, bssid, 17);
    d[k].bssid[17] = 0;
    d[k].stations = stations;
    d[k].age = age;
    if (load->listed < CONTROLLER_AP_BSS_MAX)
        load->listed++;
}

int controller_peer_bss_load(const char *mac, time_t max_age, struct peer_bss_load *load)
{
    DIR *dir;
    struct dirent *entry;
    time_t now = time(NULL);

    if (!mac || !load)
        return 0;
    memset(load, 0, sizeof(*load));
    dir = opendir(peers_dir());
    if (!dir)
        return 0;
    while ((entry = readdir(dir))) {
        time_t when;
        int stations;
        if (!is_bss_entry_name(entry->d_name, mac))
            continue;
        stations = read_bss_entry(entry->d_name, &when);
        if (stations < 0)
            continue;
        if (max_age && now - when > max_age)
            continue;
        load->stations += (unsigned int)stations;
        load->entries++;
        if (load->entries == 1 || now - when > load->age)
            load->age = now - when;
        put_detail(load, entry->d_name, (unsigned int)stations, now - when);
    }
    (void)closedir(dir);
    return load->entries ? 1 : 0;
}
