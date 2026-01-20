#include <ev.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>

#include <stdio.h>

void* my_ev_default_loop() { 
    printf("C: Calling ev_default_loop...\n");
    void* loop = ev_default_loop(0); 
    printf("C: loop = %p\n", loop);
    return loop;
}
void my_ev_io_init(ev_io* w, void (*cb)(struct ev_loop *loop, ev_io *w, int revents), int fd, int events) { 
    printf("C: ev_io_init w=%p, fd=%d\n", w, fd);
    ev_io_init(w, cb, fd, events); 
}
void my_ev_timer_init(ev_timer* w, void (*cb)(struct ev_loop *loop, ev_timer *w, int revents), double after, double repeat) { 
    printf("C: ev_timer_init w=%p, after=%f, repeat=%f\n", w, after, repeat);
    ev_timer_init(w, cb, after, repeat); 
}
void my_ev_io_start(void* loop, ev_io* w) { 
    printf("C: ev_io_start loop=%p, w=%p\n", loop, w);
    ev_io_start(loop, w); 
}
void my_ev_timer_start(void* loop, ev_timer* w) { 
    printf("C: ev_timer_start loop=%p, w=%p\n", loop, w);
    ev_timer_start(loop, w); 
}
void my_ev_run(void* loop) { 
    printf("C: ev_run loop=%p\n", loop);
    ev_run(loop, 0); 
}

int my_tuntap_init(int fd, const char* name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    return ioctl(fd, TUNSETIFF, (void *) &ifr);
}
