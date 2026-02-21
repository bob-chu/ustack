#include <ev.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>

void* my_ev_default_loop() { 
    // printf("C: Calling ev_default_loop...\n"); fflush(stdout);
    void* loop = ev_default_loop(0); 
    // printf("C: loop = %p\n", loop); fflush(stdout);
    return loop;
}
void my_ev_io_init(ev_io* w, void (*cb)(struct ev_loop *loop, ev_io *w, int revents), int fd, int events) { 
    // printf("C: ev_io_init w=%p, fd=%d\n", w, fd); fflush(stdout);
    ev_io_init(w, cb, fd, events); 
}
void my_ev_timer_init(ev_timer* w, void (*cb)(struct ev_loop *loop, ev_timer *w, int revents), double after, double repeat) { 
    // printf("C: ev_timer_init w=%p, after=%f, repeat=%f\n", w, after, repeat); fflush(stdout);
    ev_timer_init(w, cb, after, repeat); 
}
void my_ev_io_start(void* loop, ev_io* w) { 
    // printf("C: ev_io_start loop=%p, w=%p\n", loop, w); fflush(stdout);
    ev_io_start(loop, w); 
}
void my_ev_timer_start(void* loop, ev_timer* w) { 
    // printf("C: ev_timer_start loop=%p, w=%p\n", loop, w); fflush(stdout);
    ev_timer_start(loop, w); 
}
void my_ev_run(void* loop) { 
    // printf("C: ev_run loop=%p\n", loop); fflush(stdout);
    ev_run(loop, 0); 
}
void my_ev_run_once(void* loop) {
    ev_run(loop, EVRUN_ONCE);
}
void my_ev_break(void* loop, int how) {
    ev_break(loop, how);
}

#include <errno.h>

int my_tuntap_init(int fd, const char* name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    int rc = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (rc < 0) return -errno;
    return 0;
}

int my_set_if_up(const char* name) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    close(sockfd);
    return 0;
}

int my_set_if_addr(const char* name, const char* addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    
    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, addr, &sin->sin_addr);
    
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    
    // Also set netmask
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    sin = (struct sockaddr_in*)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.0", &sin->sin_addr);
    ioctl(sockfd, SIOCSIFNETMASK, &ifr);

    close(sockfd);
    return 0;
}
