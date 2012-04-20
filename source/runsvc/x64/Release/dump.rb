f = File.open ARGV[0], "rb"
col = 1
print "\n\""
f.each_byte do |b|
  print "\\x%02x" % [b]
  if col > 15
    col = 0
    print "\" +\n\""
  end
  col += 1
end
print "\"\n"