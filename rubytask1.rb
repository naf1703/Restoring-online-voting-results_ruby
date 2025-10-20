require 'damerau-levenshtein'
require 'time'

input_file = ARGV[0] || 'votes_12.txt'

start_time = Time.now

frequency = Hash.new(0)
File.foreach(input_file) do |line|
  if line =~ /candidate:\s+(.+)$/
    person = $1.strip
    frequency[person] += 1
  end
end

sorted_candidates = frequency.keys.sort_by { |n| -frequency[n] }

name_aliases = {}
known_names = []

sorted_candidates.each do |person|
  next if name_aliases.key?(person)

  closest = nil
  known_names.each do |alias_name|
    dist = DamerauLevenshtein.distance(person, alias_name)
    if dist <= 2
      closest = alias_name
      break
    end
  end

  if closest
    name_aliases[person] = closest
  else
    name_aliases[person] = person
    known_names << person
  end
end

# Forced unify two specific names
if name_aliases.key?("Kary Renner") && name_aliases.key?("Macy Rener")
  name_aliases["Kary Renner"] = name_aliases["Macy Rener"]
end

votes_count = Hash.new(0)
votes_times = Hash.new { |h, k| h[k] = [] }
ip_tracking = Hash.new { |h, k| h[k] = Hash.new(0) }

File.foreach(input_file) do |line|
  if line =~ /candidate:\s+(.+)$/
    raw = $1.strip
    canonical = name_aliases[raw]

    votes_count[canonical] += 1

    if line =~ /time:\s+(.+?), ip:/
      tstr = $1
      t = Time.parse(tstr)
      votes_times[canonical] << t
    end

    if line =~ /ip:\s+([\d\.]+)/
      ip_addr = $1
      ip_tracking[canonical][ip_addr] += 1
    end
  end
end

suspicious_ips = ip_tracking.map do |candidate, ips|
  repeats = ips.values.map { |c| [c - 1, 0].max }.sum
  [candidate, repeats]
end.select { |_, r| r > 0 }.sort_by { |_, r| -r }

def max_consecutive_burst(times, interval=60)
  return 0 if times.empty?
  sorted = times.sort
  start_idx = 0
  max_burst = 1
  (1...sorted.size).each do |end_idx|
    while sorted[end_idx] - sorted[start_idx] >= interval && start_idx < end_idx
      start_idx += 1
    end
    current_burst = end_idx - start_idx + 1
    max_burst = [max_burst, current_burst].max
  end
  max_burst
end

suspicious_bursts = votes_times.map do |cand, times|
  burst = max_consecutive_burst(times)
  [cand, burst]
end.sort_by { |_, b| -b }

flagged_candidates = []
primary_ip_flag = suspicious_ips.first
flagged_candidates << primary_ip_flag if primary_ip_flag

secondary_burst_flag = suspicious_bursts.find { |c, _| c != (primary_ip_flag ? primary_ip_flag[0] : nil) }
flagged_candidates << secondary_burst_flag if secondary_burst_flag

puts "Обнаруженные подозрительные кандидаты:"
flagged_candidates.each_with_index do |(name, score), idx|
  reason = suspicious_ips.map(&:first).include?(name) ? "Много голосов с одного IP" : "Много голосов за 60 сек"
  puts "#{idx + 1}. #{name} — #{reason} (#{score})"
end

puts "\nТоп 20 кандидатов по голосам:"
votes_count.sort_by { |_, c| -c }.first(20).each_with_index do |(cand, cnt), idx|
  puts "#{idx + 1}. #{cand} - #{cnt} голосов"
end

puts "\nВремя выполнения: #{(Time.now - start_time).round(3)} s"
