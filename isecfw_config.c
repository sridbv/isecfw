#include "isecfw_config.h"

int usage()
{
    printf("isecfw      [options]\n");
    printf("            [-I Insert rule]\n");
    printf("            [-R Remove rule]\n");
    printf("            [-A allow]\n");
    printf("            [-B deny]\n");
    printf("            [-i Ingress rule]\n");
    printf("            [-e Egress rule]\n");
    printf("            [-P protocol tcp/udp/icmp]\n");
    printf("            [-S source ip-address]\n");
    printf("            [-D destination ip-address]\n");
    printf("            [-s source port]\n");
    printf("            [-d destination port]\n");
}

void isecfw_config_process(void) {

}
int parse_and_process(int argc, char * argv[]) {
    
    bool insert = false;
    bool remove = false;
    char c;
    int fd;
    opterr = 0;
    struct isecfw_rule_arg rule;
    memset(&rule, 0, sizeof(struct isecfw_rule_arg));

    while ((c = getopt(argc, argv, "IRABeiP:S:D:s:d:")) != -1) {
        switch(c) {
            case 'I':
                insert = true;
                break;
            case 'R':
                remove = true;
                break;
            case 'i':
                rule.direction = RULE_INGRESS;
                break;
            case 'e':
                rule.direction = RULE_EGRESS;
                break;
            case 'A':
                rule.action = NET_RULE_ALLOW;
                break;
            case 'B':
                rule.action = NET_RULE_DROP;
                break;
            case 'P':
                if (!strncmp(optarg, "tcp", 3))
                    rule.proto = IPPROTO_TCP;
                else if (!strncmp(optarg, "udp", 3))
                    rule.proto = IPPROTO_UDP;
                else if (!strncmp(optarg, "icmp", 4))
                    rule.proto = IPPROTO_ICMP;
                else {
                    printf("Invalid protocol option\n");
                    usage();
                    exit(-1);
                }
                break;
            case 'S':
                rule.srcip = inet_addr(optarg);
                break;
            case 'D':
                rule.dstip = inet_addr(optarg);
                break;
            case 's':
                rule.srcport = atoi(optarg);
                break;
            case 'd':
                rule.dstport = atoi(optarg);
                break;
            default:
                break;
        }
    }
    if ((fd = open(ISECFW_DEV, O_RDWR)) == -1) {
    
        perror("device file open error:");
        return -1;
    }
    if (insert) {   
        if (ioctl(fd, ISECFW_SET_RULE, &rule) == -1) {
            close(fd);
            perror("ioctl ISECFW_SET_RULE:");
            return -1;
        }
    }
    if (remove) {
        
        if (ioctl(fd, ISECFW_DEL_RULE, &rule) == -1) {
            close(fd);
            perror("ioctl ISECFW_SET_RULE:");
            return -1;
        }
    }
    close(fd);
    return 0;
}
int main(int argc, char *argv[])
{
    int i = 0, count = 0;
    char *device = NULL;

    if (argc == 1) {
        usage();
        return 0;
    }

    parse_and_process(argc, argv);

    return 0;
            
}
