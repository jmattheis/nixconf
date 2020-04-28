{ config, pkgs, lib, ... }:

let
  blockedHostDir = "/var/lib/blockdns";
  blockedHostFile = "/var/lib/blockdns/hosts";
  updateHostsFile = pkgs.writeScriptBin "update-hosts" ''
    #!${pkgs.stdenv.shell}
    ${pkgs.curl}/bin/curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
                             https://hosts-file.net/ad_servers.txt \
                             https://adaway.org/hosts.txt \
                             https://someonewhocares.org/hosts/hosts | \
                             grep '^0.0.0.0 ' > ${blockedHostFile}
    echo Check ${blockedHostFile} and restart coredns
    chmod g+rwx ${blockedHostDir}
    chmod g+rwx ${blockedHostFile}
  '';
  settings = import ./settings.nix;
in
{
  imports =
    [
      ./hardware-configuration.nix
      ./private.nix
    ];

  boot.loader.grub.enable = true;
  boot.loader.grub.version = 2;
  boot.loader.grub.device = "/dev/sda";

  #system.autoUpgrade = {
  #  enable = true;
  #  allowReboot = true;
  #};
  console = {
    font = "Lat2-Terminus16";
    keyMap = "us";
  };
  i18n = {
    defaultLocale = "en_US.UTF-8";
  };

  time.timeZone = "Europe/Berlin";

  environment.systemPackages = with pkgs; [
    wget vim htop tmux tree restic ncdu git httpie bind vgo2nix yarn openvpn protonvpn-cli
  ];

  services = {
    nginx = {
      enable = true;
      recommendedGzipSettings = true;
      recommendedOptimisation = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;
      virtualHosts.${settings.cloudHost} = {
        enableACME = true;
        forceSSL = true;
      };
      virtualHosts.${settings.rssHost} = {
        enableACME = true;
        forceSSL = true;
        locations."/".proxyPass = "http://127.0.0.1:50000";
      };
      virtualHosts.${settings.audioHost} = {
        enableACME = true;
        forceSSL = true;
      };
      virtualHosts.${settings.dnsHost} = {
        enableACME = true;
        forceSSL = true;
        locations."/".proxyPass = "https://127.0.0.1:453";
      };
      virtualHosts.${settings.gotifyHost} = {
        enableACME = true;
        forceSSL = true;
        locations."/".proxyPass = "http://127.0.0.1:44444";
        locations."/".proxyWebsockets = true;
        locations."/".extraConfig = ''
          proxy_connect_timeout   7m;
          proxy_send_timeout      7m;
          proxy_read_timeout      7m;
        '';
      };
    };
    nextcloud = {
      package = pkgs.nextcloud18;
      enable = true;
      hostName = settings.cloudHost;
      nginx.enable = true;
      config = {
        adminpass = "changeme";
        overwriteProtocol = "https";
      };
    };
    airsonic = {
      enable = true;
      virtualHost = settings.audioHost;
      maxMemory = 600;
    };
    gotify = {
      enable = true;
      port = 44444;
    };
    miniflux = {
      enable = true;
      config.LISTEN_ADDR = "127.0.0.1:50000";
      config.BASE_URL = "https://" + settings.rssHost;
    };
    coredns = {
      enable = true;
      config = ''
	dns://.:53 tls://.:853 https://.:453 {
	  tls /var/lib/acme/${settings.dnsHost}/full.pem /var/lib/acme/${settings.dnsHost}/key.pem
	  whoami
	  errors
	  debug
	  any
	  cancel
	  dnssec
	  hosts ${blockedHostFile} {
	    fallthrough
	  }
	  forward . tls://1.1.1.1 tls://1.0.0.1 {
	    tls_servername cloudflare-dns.com
	    health_check 5s
	  }
	  cache 60
	}
      '';
    };
  };
  systemd.services.coredns.serviceConfig.DynamicUser = lib.mkForce false;
  systemd.services.coredns.serviceConfig.User = "nginx";

  networking = {
    hostName = settings.hostName;
    firewall.allowedTCPPorts = [ 80 443 453 853 ];
    firewall.allowedUDPPorts = [ ];
  };

  services.openssh = {
    enable = true;
    permitRootLogin = "no";
    passwordAuthentication = false;
    challengeResponseAuthentication = false;
  };
  security.sudo.extraConfig = ''
    %wheel      ALL=(ALL:ALL) NOPASSWD: ALL
  '';

  users.users.${settings.user.name} = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [ settings.user.sshKey ];
  };

  users.extraUsers.blockdns = {
    home = blockedHostDir;
    createHome = true;
    group = "nginx";
  };
  systemd.services.blockdns-update-cron = {
    serviceConfig.Type = "oneshot";
    serviceConfig.User = "blockdns";
    serviceConfig.WorkingDirectory = blockedHostDir;
    serviceConfig.StateDirectoryMode = "750";
    serviceConfig.ExecStart = "${updateHostsFile}/bin/update-hosts";
  };
  systemd.timers.blockdns-update-cron = {
    wantedBy = [ "timers.target" ];
    timerConfig.OnCalendar = "*-*-* 02:00:00";
    timerConfig.Unit = "blockdns-update-cron.service";
  };
  security.acme.acceptTerms = true;
  security.acme.email = settings.email;

  # This value determines the NixOS release with which your system is to be
  # compatible, in order to avoid breaking some software such as database
  # servers. You should change this only after NixOS release notes say you
  # should.
  system.stateVersion = "19.03"; # Did you read the comment?
}

