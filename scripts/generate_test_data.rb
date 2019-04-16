#!/usr/bin/env ruby

public_keys = []

key_types = %i[ssh-rsa ssh-ed25519 ecdsa]
key_sizes = {
  'ssh-rsa': [1024, 2048, 4096],
  'ssh-ed25519': [128, 256, 512],
  'ecdsa': [256, 384, 521]
}
comment_chars = ('A'..'Z').to_a + ('a'..'z').to_a + [' ', '-', '_']
options_set = ['command="uptime"', 'no-agent-forwarding', 'restrict', 'environment="LOGNAME=tricksy"', 'environment="HOME=/tmp"']

1_000.times do
  File.delete('tmpkey') if File.exist? 'tmpkey'
  File.delete('tmpkey.pub') if File.exist? 'tmpkey.pub'

  kt = key_types.sample
  ks = key_sizes[kt].sample

  comment = (0..300).to_a.sample.times.map { comment_chars.sample }.join

  `ssh-keygen -q -t #{kt} -b #{ks} -f tmpkey -C "#{comment}" -N ''`

  options = options_set.sample((0..5).to_a.sample).join(",")

  if options != ''
    public_keys << "#{options} #{File.read('tmpkey.pub')}"
  else
    public_keys << File.read('tmpkey.pub')
  end
end

File.write('test_keys.txt', public_keys.join)
