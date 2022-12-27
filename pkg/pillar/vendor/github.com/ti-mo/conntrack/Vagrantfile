boxes = {
  "centos7" => "generic/centos7",
  "precise" => "ubuntu/precise64",
  "trusty" => "ubuntu/trusty64",
  "xenial" => "ubuntu/xenial64",
}

Vagrant.configure("2") do |vagrant|
  boxes.each do |name, image|

    vagrant.vm.define name do |config|
      config.vm.box = image
      config.vm.provider "virtualbox" do |vb|
        vb.memory = "512"

        # Disable serial connection to the VM, can sometimes write log files to repo
        vb.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
      end

      config.vm.synced_folder "build/", "/build"

      # Ensure the necessary kernel modules are loaded in the VM.
      config.vm.provision "shell", inline: <<-SHELL
        modprobe -a nf_conntrack_ipv4 nf_conntrack_ipv6
      SHELL
    end

  end
end
