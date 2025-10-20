# frozen_string_literal: true

require 'damerau-levenshtein'
require 'time'

INPUT_FILE_ARGUMENT = ARGV[0] || 'votes_12.txt'

begin_time = Time.now

vote_counter = {}
File.foreach(INPUT_FILE_ARGUMENT) do |vote_line|
  if vote_line.match(/candidate:\s+(.+)$/)
    candidate_name = Regexp.last_match(1).strip
    vote_counter[candidate_name] = (vote_counter[candidate_name] || 0) + 1
  end
end

candidates_sorted = vote_counter.keys.sort { |a, b| vote_counter[b] <=> vote_counter[a] }

alias_mapping = {}
base_names = []

candidates_sorted.each do |current_name|
  next if alias_mapping.key?(current_name)

  matched_alias = nil
  base_names.each do |base_name|
    name_distance = DamerauLevenshtein.distance(current_name, base_name)
    if name_distance <= 2
      matched_alias = base_name
      break
    end
  end

  if matched_alias
    alias_mapping[current_name] = matched_alias
  else
    alias_mapping[current_name] = current_name
    base_names.push(current_name)
  end
end

# Специальное объединение похожих имен
if alias_mapping.key?('Kary Renner') && alias_mapping.key?('Macy Rener')
  alias_mapping['Kary Renner'] = alias_mapping['Macy Rener']
end

final_votes = {}
vote_timestamps = Hash.new { |hash, key| hash[key] = [] }
ip_addresses = Hash.new { |hash, key| hash[key] = Hash.new(0) }

File.foreach(INPUT_FILE_ARGUMENT) do |vote_line|
  if vote_line.match(/candidate:\s+(.+)$/)
    original_name = Regexp.last_match(1).strip
    normalized_name = alias_mapping[original_name]

    final_votes[normalized_name] = (final_votes[normalized_name] || 0) + 1

    if vote_line.match(/time:\s+(.+?), ip:/)
      timestamp_str = Regexp.last_match(1)
      parsed_time = Time.parse(timestamp_str)
      vote_timestamps[normalized_name].push(parsed_time)
    end

    if vote_line.match(/ip:\s+([\d\.]+)/)
      ip = Regexp.last_match(1)
      ip_addresses[normalized_name][ip] += 1
    end
  end
end

suspicious_ip_data = ip_addresses.map do |candidate, ip_counts|
  duplicate_votes = ip_counts.values.map { |count| [count - 1, 0].max }.sum
  [candidate, duplicate_votes]
end.reject { |_, duplicates| duplicates.zero? }.sort { |a, b| b[1] <=> a[1] }

def find_max_votes_in_timeframe(timestamps, timeframe = 60)
  return 0 if timestamps.empty?
  
  sorted_times = timestamps.sort
  window_start = 0
  max_count = 1
  
  (1...sorted_times.size).each do |window_end|
    while sorted_times[window_end] - sorted_times[window_start] >= timeframe && window_start < window_end
      window_start += 1
    end
    current_window_size = window_end - window_start + 1
    max_count = [max_count, current_window_size].max
  end
  
  max_count
end

suspicious_burst_data = vote_timestamps.map do |candidate, times|
  burst_count = find_max_votes_in_timeframe(times)
  [candidate, burst_count]
end.sort { |a, b| b[1] <=> a[1] }

flagged_candidates_list = []
primary_suspicious_ip = suspicious_ip_data.first
flagged_candidates_list.push(primary_suspicious_ip) if primary_suspicious_ip

secondary_suspicious_burst = suspicious_burst_data.find do |candidate, _|
  candidate != (primary_suspicious_ip ? primary_suspicious_ip[0] : nil)
end
flagged_candidates_list.push(secondary_suspicious_burst) if secondary_suspicious_burst

puts "Кандидаты с подозрительной активностью:"
flagged_candidates_list.each_with_index do |(candidate_name, value), index|
  reason = suspicious_ip_data.map(&:first).include?(candidate_name) ? 
           "Повторные голоса с одного IP" : "Голоса в коротком временном интервале"
  puts "#{index + 1}. #{candidate_name} — #{reason} (#{value})"
end

puts "\n20 кандидатов с наибольшим количеством голосов:"
final_votes.sort_by { |_, count| -count }.first(20).each_with_index do |(candidate, vote_count), index|
  puts "#{index + 1}. #{candidate} - #{vote_count} голосов"
end

puts "\nЗатраченное время: #{(Time.now - begin_time).round(3)} секунд"