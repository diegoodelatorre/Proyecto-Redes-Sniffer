#define _DARWIN_C_SOURCE
#define GL_SILENCE_DEPRECATION  // Silencia warnings de OpenGL deprecated en macOS

#include <iostream>
#include <pcap.h>
#include <vector>
#include <iomanip>
#include <fstream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <limits>
#include <map>
#include <set>
#include <ctime>
#include <cctype>
#include <algorithm>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

// OPENGL y GLFW
#define GL_GLEXT_PROTOTYPES
#ifdef __APPLE__
    #include <OpenGL/gl3.h>
#else
    #include <GL/gl.h>
#endif
#include "glfw3.h"

// NUKLEAR
#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#include "nuklear.h"

#define NK_GLFW_GL3_IMPLEMENTATION
#include "nuklear_glfw_gl3.h"

// Estructura principal del paquete
struct CapturedPacket {
    int id;
    int size;
    std::string mac_src;
    std::string mac_dst;
    std::string ip_src;
    std::string ip_dst;
    std::string protocol;
    std::string info_adicional;
    int port_src;
    int port_dst;
    int ttl;
    std::string timestamp;
    std::vector<u_char> raw_data;
};

// Variables globales
std::vector<CapturedPacket> packetHistory;
int packetCounter = 0;
pcap_t *globalHandle = NULL;
std::atomic<bool> keepCapturing(true);
std::atomic<bool> isPaused(true);

int selectedPacketIdx = -1;
std::string csvStatusMessage = "";

std::map<std::string, std::string>   arpTable;
std::map<std::string, std::set<int>> portScanMap;
std::vector<std::string>             alertLog;

// Helpers
std::string formatMAC(const u_char *mac) {
    char buf[20];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;
    std::tm *tm_info = std::localtime(&t);
    char buf[32];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, (int)ms.count());
    return std::string(buf);
}

void printAlert(const std::string &msg) {
    alertLog.push_back(msg);
}

// Color de cada protocolo
struct nk_color protocolColor(const std::string &proto) {
    if (proto == "TCP")  return nk_rgb(70, 140, 221);   // azul
    if (proto == "UDP")  return nk_rgb(99, 153, 34);    // verde
    if (proto == "ICMP") return nk_rgb(186, 117, 23);   // ambar
    if (proto == "ARP")  return nk_rgb(153, 53, 86);    // rosa
    return nk_rgb(136, 135, 128);                       // gris (IPv6 y otros)
}

std::string toLowerStr(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// Colores del tema claro
void applyLightTheme(struct nk_context *ctx) {
    struct nk_color table[NK_COLOR_COUNT];
    table[NK_COLOR_TEXT]                   = nk_rgba(50, 48, 44, 255);
    table[NK_COLOR_WINDOW]                 = nk_rgba(244, 243, 238, 255);
    table[NK_COLOR_HEADER]                 = nk_rgba(160, 160, 155, 255);
    table[NK_COLOR_BORDER]                 = nk_rgba(205, 203, 196, 255);
    table[NK_COLOR_BUTTON]                 = nk_rgba(234, 233, 227, 255);
    table[NK_COLOR_BUTTON_HOVER]           = nk_rgba(222, 221, 214, 255);
    table[NK_COLOR_BUTTON_ACTIVE]          = nk_rgba(208, 207, 199, 255);
    table[NK_COLOR_TOGGLE]                 = nk_rgba(220, 219, 212, 255);
    table[NK_COLOR_TOGGLE_HOVER]           = nk_rgba(205, 204, 196, 255);
    table[NK_COLOR_TOGGLE_CURSOR]          = nk_rgba(160, 158, 150, 255);
    table[NK_COLOR_SELECT]                 = nk_rgba(234, 233, 227, 255);
    table[NK_COLOR_SELECT_ACTIVE]          = nk_rgba(214, 213, 205, 255);
    table[NK_COLOR_SLIDER]                 = nk_rgba(220, 219, 212, 255);
    table[NK_COLOR_SLIDER_CURSOR]          = nk_rgba(160, 158, 150, 255);
    table[NK_COLOR_SLIDER_CURSOR_HOVER]    = nk_rgba(140, 138, 130, 255);
    table[NK_COLOR_SLIDER_CURSOR_ACTIVE]   = nk_rgba(120, 118, 110, 255);
    table[NK_COLOR_PROPERTY]               = nk_rgba(234, 233, 227, 255);
    table[NK_COLOR_EDIT]                   = nk_rgba(250, 250, 247, 255);
    table[NK_COLOR_EDIT_CURSOR]            = nk_rgba(50, 48, 44, 255);
    table[NK_COLOR_COMBO]                  = nk_rgba(234, 233, 227, 255);
    table[NK_COLOR_CHART]                  = nk_rgba(234, 233, 227, 255);
    table[NK_COLOR_CHART_COLOR]            = nk_rgba(160, 158, 150, 255);
    table[NK_COLOR_CHART_COLOR_HIGHLIGHT]  = nk_rgba(226, 75, 74, 255);
    table[NK_COLOR_SCROLLBAR]              = nk_rgba(234, 233, 227, 255);
    table[NK_COLOR_SCROLLBAR_CURSOR]       = nk_rgba(200, 198, 190, 255);
    table[NK_COLOR_SCROLLBAR_CURSOR_HOVER] = nk_rgba(185, 183, 175, 255);
    table[NK_COLOR_SCROLLBAR_CURSOR_ACTIVE]= nk_rgba(170, 168, 160, 255);
    table[NK_COLOR_TAB_HEADER]             = nk_rgba(228, 227, 220, 255);
    nk_style_from_table(ctx, table);
}

// Colores del tema oscuro
void applyDarkTheme(struct nk_context *ctx) {
    struct nk_color table[NK_COLOR_COUNT];
    table[NK_COLOR_TEXT]                   = nk_rgba(230, 230, 230, 255);
    table[NK_COLOR_WINDOW]                 = nk_rgba(35, 35, 35, 255);
    table[NK_COLOR_HEADER]                 = nk_rgba(50, 60, 75, 255);
    table[NK_COLOR_BORDER]                 = nk_rgba(65, 65, 65, 255);
    table[NK_COLOR_BUTTON]                 = nk_rgba(55, 55, 55, 255);
    table[NK_COLOR_BUTTON_HOVER]           = nk_rgba(75, 75, 75, 255);
    table[NK_COLOR_BUTTON_ACTIVE]          = nk_rgba(40, 40, 40, 255);
    table[NK_COLOR_TOGGLE]                 = nk_rgba(50, 50, 50, 255);
    table[NK_COLOR_TOGGLE_HOVER]           = nk_rgba(70, 70, 70, 255);
    table[NK_COLOR_TOGGLE_CURSOR]          = nk_rgba(120, 120, 120, 255);
    table[NK_COLOR_SELECT]                 = nk_rgba(55, 55, 55, 255);
    table[NK_COLOR_SELECT_ACTIVE]          = nk_rgba(75, 75, 75, 255);
    table[NK_COLOR_SLIDER]                 = nk_rgba(50, 50, 50, 255);
    table[NK_COLOR_SLIDER_CURSOR]          = nk_rgba(120, 120, 120, 255);
    table[NK_COLOR_SLIDER_CURSOR_HOVER]    = nk_rgba(140, 140, 140, 255);
    table[NK_COLOR_SLIDER_CURSOR_ACTIVE]   = nk_rgba(160, 160, 160, 255);
    table[NK_COLOR_PROPERTY]               = nk_rgba(55, 55, 55, 255);
    table[NK_COLOR_EDIT]                   = nk_rgba(25, 25, 25, 255);
    table[NK_COLOR_EDIT_CURSOR]            = nk_rgba(230, 230, 230, 255);
    table[NK_COLOR_COMBO]                  = nk_rgba(55, 55, 55, 255);
    table[NK_COLOR_CHART]                  = nk_rgba(55, 55, 55, 255);
    table[NK_COLOR_CHART_COLOR]            = nk_rgba(120, 120, 120, 255);
    table[NK_COLOR_CHART_COLOR_HIGHLIGHT]  = nk_rgba(226, 75, 74, 255);
    table[NK_COLOR_SCROLLBAR]              = nk_rgba(40, 40, 40, 255);
    table[NK_COLOR_SCROLLBAR_CURSOR]       = nk_rgba(70, 70, 70, 255);
    table[NK_COLOR_SCROLLBAR_CURSOR_HOVER] = nk_rgba(90, 90, 90, 255);
    table[NK_COLOR_SCROLLBAR_CURSOR_ACTIVE]= nk_rgba(110, 110, 110, 255);
    table[NK_COLOR_TAB_HEADER]             = nk_rgba(45, 45, 45, 255);
    nk_style_from_table(ctx, table);
}

// Devuelve true si el paquete cumple con los filtros activos
bool matchesFilter(const CapturedPacket &p, const std::string &protoFilter,
                   const std::string &fIpSrc, const std::string &fIpDst,
                   const std::string &fPortSrc, const std::string &fPortDst,
                   const std::string &fMacSrc, const std::string &fMacDst) {
    // --- FILTROS ---
    // Protocolo
    if (protoFilter != "Todos" && p.protocol != protoFilter) return false;
    
    // IP Origen
    if (!fIpSrc.empty() && p.ip_src.find(fIpSrc) == std::string::npos) return false;
    
    // IP Destino
    if (!fIpDst.empty() && p.ip_dst.find(fIpDst) == std::string::npos) return false;
    
    // Puerto Origen
    if (!fPortSrc.empty()) {
        std::string pSrcStr = (p.port_src >= 0) ? std::to_string(p.port_src) : "";
        if (pSrcStr.find(fPortSrc) == std::string::npos) return false;
    }
    
    // Puerto Destino
    if (!fPortDst.empty()) {
        std::string pDstStr = (p.port_dst >= 0) ? std::to_string(p.port_dst) : "";
        if (pDstStr.find(fPortDst) == std::string::npos) return false;
    }
    
    // MAC Origen (ignora las mayusculas y minusculas)
    if (!fMacSrc.empty() && toLowerStr(p.mac_src).find(toLowerStr(fMacSrc)) == std::string::npos) return false;
    
    // MAC Destino (también las ignora)
    if (!fMacDst.empty() && toLowerStr(p.mac_dst).find(toLowerStr(fMacDst)) == std::string::npos) return false;

    return true; // Si cumple con todos los filtros
}

// Detección de posibles anomalias
void checkARPSpoofing(const std::string &ip, const std::string &mac) {
    auto it = arpTable.find(ip);
    if (it == arpTable.end()) {
        arpTable[ip] = mac;
    } else if (it->second != mac) {
        printAlert("ARP SPOOFING! IP " + ip + " cambia de MAC " + it->second + " a " + mac);
        arpTable[ip] = mac;
    }
}

void checkPortScan(const std::string &ip_src, int port_dst) {
    if (port_dst <= 0) return;
    portScanMap[ip_src].insert(port_dst);
    if (portScanMap[ip_src].size() == 21)
        printAlert("PORT SCAN desde " + ip_src + " (mas de 20 puertos distintos)");
}

// Callback de la captura
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!keepCapturing) return;

    packetCounter++;
    CapturedPacket cap;
    cap.id        = packetCounter;
    cap.size      = pkthdr->len;
    cap.timestamp = getCurrentTimestamp();
    cap.raw_data.assign(packet, packet + pkthdr->len);

    struct ether_header *ethHeader = (struct ether_header *) packet;
    cap.mac_src = formatMAC(ethHeader->ether_shost);
    cap.mac_dst = formatMAC(ethHeader->ether_dhost);

    cap.ip_src         = "N/A";
    cap.ip_dst         = "N/A";
    cap.protocol       = "OTRO";
    cap.info_adicional = "-";
    cap.port_src       = -1;
    cap.port_dst       = -1;
    cap.ttl            = 0;

    uint16_t etherType = ntohs(ethHeader->ether_type);

    if (etherType == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        cap.ip_src = inet_ntoa(ipHeader->ip_src);
        char ipDstBuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_dst), ipDstBuf, INET_ADDRSTRLEN);
        cap.ip_dst = std::string(ipDstBuf);
        cap.ttl = ipHeader->ip_ttl;
        int ipHL = ipHeader->ip_hl * 4;

        if (ipHeader->ip_p == IPPROTO_TCP) {
            cap.protocol = "TCP";
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ipHL);
            cap.port_src = ntohs(tcp->th_sport);
            cap.port_dst = ntohs(tcp->th_dport);
            cap.info_adicional = "Ports: " + std::to_string(cap.port_src) + " -> " + std::to_string(cap.port_dst);
            checkPortScan(cap.ip_src, cap.port_dst);
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            cap.protocol = "UDP";
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + ipHL);
            cap.port_src = ntohs(udp->uh_sport);
            cap.port_dst = ntohs(udp->uh_dport);
            cap.info_adicional = "Ports: " + std::to_string(cap.port_src) + " -> " + std::to_string(cap.port_dst);
            checkPortScan(cap.ip_src, cap.port_dst);
        } else if (ipHeader->ip_p == IPPROTO_ICMP) {
            cap.protocol = "ICMP";
            cap.info_adicional = "Control Message (Ping)";
        } else {
            cap.protocol = "IPv4";
            cap.info_adicional = "Proto: " + std::to_string(ipHeader->ip_p);
        }
    } else if (etherType == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, s, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_dst, d, INET6_ADDRSTRLEN);
        cap.ip_src = s; cap.ip_dst = d; cap.ttl = ip6->ip6_hops;
        int ip6HL = sizeof(struct ip6_hdr);
        if (ip6->ip6_nxt == IPPROTO_TCP) {
            cap.protocol = "TCP";
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip6HL);
            cap.port_src = ntohs(tcp->th_sport); cap.port_dst = ntohs(tcp->th_dport);
            cap.info_adicional = "IPv6 Ports: " + std::to_string(cap.port_src) + " -> " + std::to_string(cap.port_dst);
        } else if (ip6->ip6_nxt == IPPROTO_UDP) {
            cap.protocol = "UDP";
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + ip6HL);
            cap.port_src = ntohs(udp->uh_sport); cap.port_dst = ntohs(udp->uh_dport);
            cap.info_adicional = "IPv6 Ports: " + std::to_string(cap.port_src) + " -> " + std::to_string(cap.port_dst);
        } else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
            cap.protocol = "ICMP"; cap.info_adicional = "ICMPv6 Message";
        }
    } else if (etherType == ETHERTYPE_ARP) {
        cap.protocol = "ARP";
        struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
        char ipS[INET_ADDRSTRLEN], ipD[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, ipS, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp->arp_tpa, ipD, INET_ADDRSTRLEN);
        cap.ip_src = ipS; cap.ip_dst = ipD;
        std::string macSender = formatMAC(arp->arp_sha);
        uint16_t op = ntohs(arp->arp_op);
        if (op == ARPOP_REQUEST) {
            cap.info_adicional = (cap.ip_src == cap.ip_dst)
                ? "[Gratuitous ARP] " + cap.ip_src
                : "Who has " + cap.ip_dst + "? Tell " + cap.ip_src;
        } else if (op == ARPOP_REPLY) {
            cap.info_adicional = "Response: " + cap.ip_src + " is at " + macSender;
            checkARPSpoofing(cap.ip_src, macSender);
        }
    }

    packetHistory.push_back(cap);
}

void runCapture() {
    while (keepCapturing) {
        if (!isPaused) pcap_dispatch(globalHandle, 10, packetHandler, NULL);
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
}

// Exportar CSV
void exportToCSV() {
    std::ofstream file("captura_trafico.csv");
    if (!file.is_open()) { csvStatusMessage = "Error al crear CSV"; return; }
    file << "No.,Timestamp,Protocolo,Origen,Destino,Detalles,Tamano,TTL\n";
    for (const auto &p : packetHistory)
        file << p.id << "," << p.timestamp << "," << p.protocol << ","
             << p.ip_src << "," << p.ip_dst << "," << p.info_adicional << ","
             << p.size << "," << p.ttl << "\n";
    file.close();
    csvStatusMessage = "Guardado como 'captura_trafico.csv'";
}

// Funcion main
int main() {
    // LIBPCAP
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDevices;
    std::string iface = "en0";

    if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
        std::cerr << "Error: " << errorBuffer << "\n"; return 1;
    }
    bool found = false;
    for (pcap_if_t *d = allDevices; d != NULL; d = d->next)
        if (std::string(d->name) == "en0") { found = true; break; }
    if (!found && allDevices != NULL) iface = allDevices->name;
    pcap_freealldevs(allDevices);

    globalHandle = pcap_create(iface.c_str(), errorBuffer);
    if (!globalHandle) { std::cerr << "Error: " << errorBuffer << "\n"; return 1; }
    pcap_set_snaplen(globalHandle, 65535);
    pcap_set_promisc(globalHandle, 1);
    pcap_set_timeout(globalHandle, 10);
    pcap_set_buffer_size(globalHandle, 4 * 1024 * 1024);
    if (pcap_activate(globalHandle) < 0) { std::cerr << "Error activando interfaz\n"; return 1; }
    pcap_setnonblock(globalHandle, 1, errorBuffer);

    // GLFW
    glfwInit();
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE); // Requerido en macOS

    GLFWwindow *window = glfwCreateWindow(1280, 900, "Packet Sniffer - Proyecto Redes I", NULL, NULL);
    if (!window) { glfwTerminate(); return -1; }
    glfwMakeContextCurrent(window);

    // NUKLEAR
    struct nk_glfw glfw = {0};
    struct nk_context *ctx = nk_glfw3_init(&glfw, window, NK_GLFW3_INSTALL_CALLBACKS);

    struct nk_font_atlas *atlas;
    nk_glfw3_font_stash_begin(&glfw, &atlas);
    nk_glfw3_font_stash_end(&glfw);
    applyLightTheme(ctx);

    // Hilo de captura
    keepCapturing = true;
    isPaused = true;
    std::thread captureThread(runCapture);

    // Para los 6 inputs de los filtros
    char fIpSrc[64] = {0};   int lenIpSrc = 0;
    char fIpDst[64] = {0};   int lenIpDst = 0;
    char fPortSrc[64] = {0}; int lenPortSrc = 0;
    char fPortDst[64] = {0}; int lenPortDst = 0;
    char fMacSrc[64] = {0};  int lenMacSrc = 0;
    char fMacDst[64] = {0};  int lenMacDst = 0;
    int  protoFilterIdx = 0;
    const char* protoFilterNames[5] = {"Todos", "TCP", "UDP", "ICMP", "ARP"};

    bool isDarkMode = false;

    // Variables para el auto-scroll
    nk_uint table_scroll_x = 0;
    nk_uint table_scroll_y = 0;
    int autoScroll = 1; // Activado por default
    size_t lastPacketCount = 0;

    // Loop principal
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        nk_glfw3_new_frame(&glfw);  // pasa &glfw

        if (nk_begin(ctx, "Packet Sniffer", nk_rect(5, 5, 1270, 890),
                     NK_WINDOW_BORDER | NK_WINDOW_TITLE)) {

            // Botones de control de las capturas
            nk_layout_row_template_begin(ctx, 35);
            nk_layout_row_template_push_static(ctx, 150); // Play
            nk_layout_row_template_push_static(ctx, 150); // Limpiar
            nk_layout_row_template_push_static(ctx, 150); // CSV
            nk_layout_row_template_push_dynamic(ctx);     // Espacio vacío
            nk_layout_row_template_push_static(ctx, 150); // Modo Oscuro
            nk_layout_row_template_end(ctx);

            // Texto blanco en esos botones de control
            nk_style_push_color(ctx, &ctx->style.button.text_normal, nk_rgb(255, 255, 255));
            nk_style_push_color(ctx, &ctx->style.button.text_hover, nk_rgb(255, 255, 255));
            nk_style_push_color(ctx, &ctx->style.button.text_active, nk_rgb(255, 255, 255));

            // Botón Reanudar / Pausar
            struct nk_color color_play = nk_rgb(40, 160, 85); 
            struct nk_color color_pause = nk_rgb(190, 50, 50);  
            struct nk_color btn_status = isPaused ? color_play : color_pause;
            nk_style_push_style_item(ctx, &ctx->style.button.normal, nk_style_item_color(btn_status));
            nk_style_push_style_item(ctx, &ctx->style.button.hover, nk_style_item_color(btn_status));
            nk_style_push_style_item(ctx, &ctx->style.button.active, nk_style_item_color(btn_status));
            if (nk_button_label(ctx, isPaused ? "> Reanudar" : "|| Pausar")) isPaused = !isPaused;
            nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx);

            // Botón Limpiar
            struct nk_color color_clear = nk_rgb(60, 130, 180);
            nk_style_push_style_item(ctx, &ctx->style.button.normal, nk_style_item_color(color_clear));
            nk_style_push_style_item(ctx, &ctx->style.button.hover, nk_style_item_color(color_clear));
            nk_style_push_style_item(ctx, &ctx->style.button.active, nk_style_item_color(color_clear));
            if (nk_button_label(ctx, "Limpiar")) {
                packetHistory.clear(); packetCounter = 0; selectedPacketIdx = -1;
                csvStatusMessage = ""; arpTable.clear(); portScanMap.clear(); alertLog.clear();
            }
            nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx);

            // Botón Exportar CSV
            struct nk_color color_csv = nk_rgb(205, 150, 40);
            nk_style_push_style_item(ctx, &ctx->style.button.normal, nk_style_item_color(color_csv));
            nk_style_push_style_item(ctx, &ctx->style.button.hover, nk_style_item_color(color_csv));
            nk_style_push_style_item(ctx, &ctx->style.button.active, nk_style_item_color(color_csv));
            if (nk_button_label(ctx, "Exportar CSV")) exportToCSV();
            nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx);

            // Para que el texto blanco de los botones de control no afecte en los demas botones
            nk_style_pop_color(ctx); nk_style_pop_color(ctx); nk_style_pop_color(ctx);

            // Espacio vacio
            nk_spacing(ctx, 1);

            // Botón de Modo Oscuro / Claro
            struct nk_color color_theme = isDarkMode ? nk_rgb(80, 80, 80) : nk_rgb(180, 180, 180);
            nk_style_push_style_item(ctx, &ctx->style.button.normal, nk_style_item_color(color_theme));
            nk_style_push_style_item(ctx, &ctx->style.button.hover, nk_style_item_color(color_theme));
            nk_style_push_style_item(ctx, &ctx->style.button.active, nk_style_item_color(color_theme));
            if (nk_button_label(ctx, isDarkMode ? "Modo Claro" : "Modo Oscuro")) {
                isDarkMode = !isDarkMode;
                if (isDarkMode) applyDarkTheme(ctx);
                else applyLightTheme(ctx);
            }
            nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx);

            // Estado CSV
            if (!csvStatusMessage.empty()) {
                nk_layout_row_dynamic(ctx, 20, 1);
                nk_label(ctx, csvStatusMessage.c_str(), NK_TEXT_LEFT);
            }

            struct nk_color textHintColor = isDarkMode ? nk_rgb(180, 180, 180) : textHintColor;
            struct nk_color textMuteColor = isDarkMode ? nk_rgb(140, 140, 140) : textMuteColor;
            // Metricas (paquetes, alertas, estado e interfaz)
            nk_layout_row_dynamic(ctx, 56, 4);

            // fondo de los bloques de esas metricas
            struct nk_color card_bg = isDarkMode ? nk_rgb(35, 35, 35) : nk_rgb(220, 220, 215);
            nk_style_push_style_item(ctx, &ctx->style.window.fixed_background, nk_style_item_color(card_bg));
            // Color del texto de las metricas
            struct nk_color cardTitleColor = isDarkMode ? nk_rgb(180, 180, 180) : nk_rgb(0, 0, 0);

            if (nk_group_begin(ctx, "card_packets", NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR)) {
                nk_layout_row_dynamic(ctx, 16, 1);
                nk_label_colored(ctx, "Paquetes", NK_TEXT_LEFT, cardTitleColor);
                char buf[32];
                snprintf(buf, sizeof(buf), "%d", (int)packetHistory.size());
                nk_layout_row_dynamic(ctx, 24, 1);
                nk_label(ctx, buf, NK_TEXT_LEFT);
                nk_group_end(ctx);
            }
            if (nk_group_begin(ctx, "card_alerts", NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR)) {
                nk_layout_row_dynamic(ctx, 16, 1);
                nk_label_colored(ctx, "Alertas", NK_TEXT_LEFT, cardTitleColor);
                char buf[32];
                snprintf(buf, sizeof(buf), "%d", (int)alertLog.size());
                nk_layout_row_dynamic(ctx, 24, 1);
                struct nk_color alertColor = alertLog.empty() ? textMuteColor : nk_rgb(226, 75, 74);
                nk_label_colored(ctx, buf, NK_TEXT_LEFT, alertColor);
                nk_group_end(ctx);
            }
            if (nk_group_begin(ctx, "card_status", NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR)) {
                nk_layout_row_dynamic(ctx, 16, 1);
                nk_label_colored(ctx, "Estado", NK_TEXT_LEFT, cardTitleColor);
                nk_layout_row_dynamic(ctx, 24, 1);
                struct nk_color stColor = isPaused ? textMuteColor : nk_rgb(40, 160, 85);
                nk_label_colored(ctx, isPaused ? "Pausado" : "Capturando", NK_TEXT_LEFT, stColor);
                nk_group_end(ctx);
            }
            if (nk_group_begin(ctx, "card_iface", NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR)) {
                nk_layout_row_dynamic(ctx, 16, 1);
                nk_label_colored(ctx, "Interfaz", NK_TEXT_LEFT, cardTitleColor);
                nk_layout_row_dynamic(ctx, 24, 1);
                nk_label(ctx, iface.c_str(), NK_TEXT_LEFT);
                nk_group_end(ctx);
            }

            // Restaurar las ventanas de su color normal
            nk_style_pop_style_item(ctx);

            // Estadisticas de los protocolos en los que se detectan los paquetes
            int cTCP = 0, cUDP = 0, cICMP = 0, cARP = 0, cOther = 0;
            int totalPkts = packetHistory.size();
            if (totalPkts > 0) {
                for (const auto &p : packetHistory) {
                    if (p.protocol == "TCP") cTCP++;
                    else if (p.protocol == "UDP") cUDP++;
                    else if (p.protocol == "ICMP") cICMP++;
                    else if (p.protocol == "ARP") cARP++;
                    else cOther++;
                }

                nk_layout_row_dynamic(ctx, 15, 1);
                nk_label_colored(ctx, "Estadisticas de los protocolos de los paquetes:", NK_TEXT_LEFT, textHintColor);
                
                nk_layout_row_dynamic(ctx, 22, 5);
                char bufStat[64];
                
                snprintf(bufStat, sizeof(bufStat), "TCP: %d%%", (cTCP * 100) / totalPkts);
                nk_label_colored(ctx, bufStat, NK_TEXT_CENTERED, protocolColor("TCP"));
                
                snprintf(bufStat, sizeof(bufStat), "UDP: %d%%", (cUDP * 100) / totalPkts);
                nk_label_colored(ctx, bufStat, NK_TEXT_CENTERED, protocolColor("UDP"));
                
                snprintf(bufStat, sizeof(bufStat), "ICMP: %d%%", (cICMP * 100) / totalPkts);
                nk_label_colored(ctx, bufStat, NK_TEXT_CENTERED, protocolColor("ICMP"));
                
                snprintf(bufStat, sizeof(bufStat), "ARP: %d%%", (cARP * 100) / totalPkts);
                nk_label_colored(ctx, bufStat, NK_TEXT_CENTERED, protocolColor("ARP"));
                
                snprintf(bufStat, sizeof(bufStat), "Otros: %d%%", (cOther * 100) / totalPkts);
                nk_label_colored(ctx, bufStat, NK_TEXT_CENTERED, protocolColor("OTRO"));
            }

            // Mostrar la alerta mas reciente si es que la hay
            if (!alertLog.empty()) {
                nk_layout_row_dynamic(ctx, 20, 1);
                char alertLine[512];
                snprintf(alertLine, sizeof(alertLine), "[!] %s", alertLog.back().c_str());
                nk_label_colored(ctx, alertLine, NK_TEXT_LEFT, nk_rgb(226, 75, 74));
            }

            // Los 7 filtros implementados de manera simultanea
            nk_layout_row_dynamic(ctx, 18, 2); // 2 columnas
            nk_label_colored(ctx, "Filtros Individuales (Dejar en blanco para omitir):", NK_TEXT_LEFT, textHintColor);

            // Titulos de los filtros de texto
            nk_layout_row_dynamic(ctx, 16, 6);
            nk_label(ctx, "IP Origen", NK_TEXT_LEFT);
            nk_label(ctx, "IP Destino", NK_TEXT_LEFT);
            nk_label(ctx, "Port Origen", NK_TEXT_LEFT);
            nk_label(ctx, "Port Destino", NK_TEXT_LEFT);
            nk_label(ctx, "MAC Origen", NK_TEXT_LEFT);
            nk_label(ctx, "MAC Destino", NK_TEXT_LEFT);

            // Inputs para los filtros
            nk_layout_row_dynamic(ctx, 28, 6);
            nk_edit_string(ctx, NK_EDIT_FIELD, fIpSrc, &lenIpSrc, sizeof(fIpSrc) - 1, nk_filter_default);
            nk_edit_string(ctx, NK_EDIT_FIELD, fIpDst, &lenIpDst, sizeof(fIpDst) - 1, nk_filter_default);
            nk_edit_string(ctx, NK_EDIT_FIELD, fPortSrc, &lenPortSrc, sizeof(fPortSrc) - 1, nk_filter_default);
            nk_edit_string(ctx, NK_EDIT_FIELD, fPortDst, &lenPortDst, sizeof(fPortDst) - 1, nk_filter_default);
            nk_edit_string(ctx, NK_EDIT_FIELD, fMacSrc, &lenMacSrc, sizeof(fMacSrc) - 1, nk_filter_default);
            nk_edit_string(ctx, NK_EDIT_FIELD, fMacDst, &lenMacDst, sizeof(fMacDst) - 1, nk_filter_default);
            nk_layout_row_dynamic(ctx, 26, 5);
            for (int i = 0; i < 5; ++i) {
                bool active = (protoFilterIdx == i);
                struct nk_color tint = protocolColor(protoFilterNames[i]);
                
                // Colores inactivos
                struct nk_color bg_inactive = isDarkMode ? nk_rgb(55, 55, 55) : nk_rgb(234, 233, 227);
                struct nk_color bg_hover    = isDarkMode ? nk_rgb(75, 75, 75) : nk_rgb(222, 221, 214);
                
                // Condicion de tomar cada uno su color si esta activo
                struct nk_color btn_normal = active ? tint : bg_inactive;
                struct nk_color btn_hover_state = active ? tint : bg_hover;
                
                // Color de su texto
                struct nk_color text_color = active ? nk_rgb(255, 255, 255) : (isDarkMode ? nk_rgb(230, 230, 230) : nk_rgb(50, 48, 44));

                // Los fondos ya aplicados
                nk_style_push_style_item(ctx, &ctx->style.button.normal, nk_style_item_color(btn_normal));
                nk_style_push_style_item(ctx, &ctx->style.button.hover, nk_style_item_color(btn_hover_state));
                nk_style_push_style_item(ctx, &ctx->style.button.active, nk_style_item_color(tint));
                
                // Los colores de texto ya aplicados
                nk_style_push_color(ctx, &ctx->style.button.text_normal, text_color);
                nk_style_push_color(ctx, &ctx->style.button.text_hover, text_color);
                nk_style_push_color(ctx, &ctx->style.button.text_active, nk_rgb(255, 255, 255));

                // El boton ya dibujado
                if (nk_button_label(ctx, protoFilterNames[i]))
                    protoFilterIdx = i;

                // Se limpia la pila de estilos de Nuklear
                nk_style_pop_color(ctx); nk_style_pop_color(ctx); nk_style_pop_color(ctx);
                nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx);
            }

            std::string activeProtoFilter = protoFilterNames[protoFilterIdx];
            std::string strIpSrc(fIpSrc, lenIpSrc);
            std::string strIpDst(fIpDst, lenIpDst);
            std::string strPortSrc(fPortSrc, lenPortSrc);
            std::string strPortDst(fPortDst, lenPortDst);
            std::string strMacSrc(fMacSrc, lenMacSrc);
            std::string strMacDst(fMacDst, lenMacDst);

            // Area 1: Tabla de trafico
            nk_layout_row_dynamic(ctx, 270, 1);
            
            // auto-scroll
            if (autoScroll && packetHistory.size() > lastPacketCount) {
                // Se va hasta el fondo de la tabla con los paquetes
                table_scroll_y = 9999999; 
            }
            lastPacketCount = packetHistory.size();

            if (nk_group_scrolled_offset_begin(ctx, &table_scroll_x, &table_scroll_y, "Area 1: Trafico Capturado", NK_WINDOW_BORDER | NK_WINDOW_TITLE)) {
                // Headers de las columnas
                nk_layout_row_dynamic(ctx, 22, 6);
                nk_label(ctx, "No.",       NK_TEXT_LEFT);
                nk_label(ctx, "Timestamp", NK_TEXT_LEFT);
                nk_label(ctx, "Protocolo", NK_TEXT_LEFT);
                nk_label(ctx, "Origen",    NK_TEXT_LEFT);
                nk_label(ctx, "Destino",   NK_TEXT_LEFT);
                nk_label(ctx, "Tamano",    NK_TEXT_LEFT);

                // Filas de los paquetes aplicando todos los filtros
                bool anyVisible = false;
                int rowCounter = 0;
                struct nk_color rowBgA = isDarkMode ? nk_rgba(45, 45, 45, 255) : nk_rgba(244, 243, 238, 255);
                struct nk_color rowBgB = isDarkMode ? nk_rgba(38, 38, 38, 255) : nk_rgba(231, 230, 222, 255);
                struct nk_color rowBgSelected = isDarkMode ? nk_rgba(70, 100, 130, 255) : nk_rgba(213, 228, 246, 255);
                struct nk_color borderDefault = isDarkMode ? nk_rgba(65, 65, 65, 255) : nk_rgba(205, 203, 196, 255);
                struct nk_color borderSelected = isDarkMode ? nk_rgba(100, 150, 220, 255) : nk_rgba(55, 120, 200, 255);

                for (size_t i = 0; i < packetHistory.size(); ++i) {
                    const auto &p = packetHistory[i];
                    if (!matchesFilter(p, activeProtoFilter, strIpSrc, strIpDst, strPortSrc, strPortDst, strMacSrc, strMacDst)) continue;
                    anyVisible = true;

                    bool isSelected = (selectedPacketIdx >= 0 && (size_t)selectedPacketIdx == i);
                    struct nk_color rowBg = isSelected ? rowBgSelected
                                          : (rowCounter % 2 == 0 ? rowBgA : rowBgB);

                    char rowId[16];
                    snprintf(rowId, sizeof(rowId), "row_%d", p.id);

                    nk_style_push_style_item(ctx, &ctx->style.window.fixed_background, nk_style_item_color(rowBg));
                    nk_style_push_color(ctx, &ctx->style.window.border_color, isSelected ? borderSelected : borderDefault);

                    nk_layout_row_dynamic(ctx, 28, 1);
                    if (nk_group_begin(ctx, rowId, NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR)) {
                        nk_layout_row_dynamic(ctx, 20, 6);
                        char idStr[32];
                        snprintf(idStr, sizeof(idStr), "#%d", p.id);
                        
                        // Colores del boton dependiendo del tema
                        struct nk_color btn_id_bg = isDarkMode ? nk_rgb(65, 65, 65) : nk_rgb(220, 220, 220);
                        struct nk_color btn_id_hover = isDarkMode ? nk_rgb(85, 85, 85) : nk_rgb(200, 200, 200);
                        struct nk_color btn_id_text = isDarkMode ? nk_rgb(240, 240, 240) : nk_rgb(30, 30, 30);

                        // Forzar los estilos solo a este boton
                        nk_style_push_style_item(ctx, &ctx->style.button.normal, nk_style_item_color(btn_id_bg));
                        nk_style_push_style_item(ctx, &ctx->style.button.hover, nk_style_item_color(btn_id_hover));
                        nk_style_push_style_item(ctx, &ctx->style.button.active, nk_style_item_color(btn_id_bg));
                        nk_style_push_color(ctx, &ctx->style.button.text_normal, btn_id_text);
                        nk_style_push_color(ctx, &ctx->style.button.text_hover, btn_id_text);
                        nk_style_push_color(ctx, &ctx->style.button.text_active, btn_id_text);

                        if (nk_button_label(ctx, idStr)) {
                            selectedPacketIdx = (int)i;
                            autoScroll = 0;
                        }

                        // Se quitan esos estilos forzados para que no afecten a los demas
                        nk_style_pop_color(ctx); nk_style_pop_color(ctx); nk_style_pop_color(ctx);
                        nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx); nk_style_pop_style_item(ctx);
                        nk_label(ctx, p.timestamp.c_str(), NK_TEXT_LEFT);
                        nk_label_colored(ctx, p.protocol.c_str(), NK_TEXT_LEFT, protocolColor(p.protocol));
                        nk_label(ctx, p.ip_src.c_str(), NK_TEXT_LEFT);
                        nk_label(ctx, p.ip_dst.c_str(), NK_TEXT_LEFT);
                        char szStr[32];
                        snprintf(szStr, sizeof(szStr), "%dB", p.size);
                        nk_label(ctx, szStr, NK_TEXT_LEFT);
                        nk_group_end(ctx);
                    }

                    nk_style_pop_color(ctx);
                    nk_style_pop_style_item(ctx);
                    rowCounter++;
                }
                if (!anyVisible) {
                    nk_layout_row_dynamic(ctx, 20, 1);
                    nk_label_colored(ctx,
                        packetHistory.empty() ? "Esperando trafico..." : "Sin paquetes que coincidan con el filtro.",
                        NK_TEXT_LEFT, nk_rgb(115, 113, 106));
                }
                nk_group_end(ctx);
            }

            // Checkbox del auto-scroll
            nk_layout_row_dynamic(ctx, 20, 1);
            nk_checkbox_label(ctx, "Auto-Scroll hacia los nuevos paquetes", &autoScroll);

            nk_layout_row_dynamic(ctx, 5, 1); // separador

            nk_layout_row_dynamic(ctx, 340, 2);

            // Area 2: Detalle por capas
            if (nk_group_begin(ctx, "Area 2: Capas del Paquete", NK_WINDOW_BORDER | NK_WINDOW_TITLE)) {
                nk_layout_row_dynamic(ctx, 20, 1);
                if (selectedPacketIdx >= 0 && selectedPacketIdx < (int)packetHistory.size()) {
                    const auto &p = packetHistory[selectedPacketIdx];
                    char line[256];

                    snprintf(line, sizeof(line), "Timestamp: %s", p.timestamp.c_str());
                    nk_label(ctx, line, NK_TEXT_LEFT);

                    nk_label(ctx, "[CAPA 2 - ETHERNET]", NK_TEXT_LEFT);
                    snprintf(line, sizeof(line), "  MAC Origen:  %s", p.mac_src.c_str());
                    nk_label(ctx, line, NK_TEXT_LEFT);
                    snprintf(line, sizeof(line), "  MAC Destino: %s", p.mac_dst.c_str());
                    nk_label(ctx, line, NK_TEXT_LEFT);

                    nk_label(ctx, "[CAPA 3 - RED]", NK_TEXT_LEFT);
                    snprintf(line, sizeof(line), "  IP Origen:  %s", p.ip_src.c_str());
                    nk_label(ctx, line, NK_TEXT_LEFT);
                    snprintf(line, sizeof(line), "  IP Destino: %s", p.ip_dst.c_str());
                    nk_label(ctx, line, NK_TEXT_LEFT);
                    snprintf(line, sizeof(line), "  TTL/Hops:   %d", p.ttl);
                    nk_label(ctx, line, NK_TEXT_LEFT);

                    nk_label(ctx, "[CAPA 4 - TRANSPORTE]", NK_TEXT_LEFT);
                    nk_layout_row_dynamic(ctx, 20, 2);
                    nk_label(ctx, "  Protocolo:", NK_TEXT_LEFT);
                    nk_label_colored(ctx, p.protocol.c_str(), NK_TEXT_LEFT, protocolColor(p.protocol));
                    nk_layout_row_dynamic(ctx, 20, 1);
                    snprintf(line, sizeof(line), "  Detalles:  %s", p.info_adicional.c_str());
                    nk_label(ctx, line, NK_TEXT_LEFT);
                    snprintf(line, sizeof(line), "  Tamano:    %d bytes", p.size);
                    nk_label(ctx, line, NK_TEXT_LEFT);
                } else {
                    nk_label(ctx, "Selecciona un paquete del Area 1.", NK_TEXT_LEFT);
                }
                nk_group_end(ctx);
            }

            // Area 3: Hexadecimal y ASCII
            if (nk_group_begin(ctx, "Area 3: Volcado Hex / ASCII", NK_WINDOW_BORDER | NK_WINDOW_TITLE)) {
                nk_layout_row_dynamic(ctx, 18, 1);
                if (selectedPacketIdx >= 0 && selectedPacketIdx < (int)packetHistory.size()) {
                    const auto &p = packetHistory[selectedPacketIdx];
                    for (size_t i = 0; i < p.raw_data.size(); i += 16) {
                        char row[128];
                        int n = snprintf(row, sizeof(row), "%04X:  ", (int)i);
                        for (size_t j = 0; j < 16; ++j) {
                            if (i + j < p.raw_data.size())
                                n += snprintf(row + n, sizeof(row) - n, "%02X ", p.raw_data[i + j]);
                            else
                                n += snprintf(row + n, sizeof(row) - n, "   ");
                        }
                        n += snprintf(row + n, sizeof(row) - n, " | ");
                        for (size_t j = 0; j < 16 && i + j < p.raw_data.size(); ++j) {
                            char c = p.raw_data[i + j];
                            n += snprintf(row + n, sizeof(row) - n, "%c", (c >= 32 && c <= 126) ? c : '.');
                        }
                        nk_label(ctx, row, NK_TEXT_LEFT);
                    }
                } else {
                    nk_label(ctx, "Esperando seleccion de paquete...", NK_TEXT_LEFT);
                }
                nk_group_end(ctx);
            }
        }
        nk_end(ctx);

        // Render
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        if (isDarkMode) glClearColor(0.12f, 0.12f, 0.12f, 1.0f);
        else glClearColor(0.957f, 0.953f, 0.933f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        nk_glfw3_render(&glfw, NK_ANTI_ALIASING_ON, 512 * 1024, 128 * 1024);
        glfwSwapBuffers(window);
    }

    // Cleanup
    keepCapturing = false;
    if (captureThread.joinable()) captureThread.join();
    nk_glfw3_shutdown(&glfw);
    glfwTerminate();
    pcap_close(globalHandle);
    return 0;
}
