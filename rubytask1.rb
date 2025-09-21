require 'set'
require 'time'

class VoteAnalyzer
  def initialize(file_path)
    @file_path = file_path
    @candidate_votes = Hash.new(0)
    @candidate_names = Set.new
    @ip_votes = Hash.new { |h, k| h[k] = [] }
    @candidate_ips = Hash.new { |h, k| h[k] = Set.new }
    @original_names = {}
    @vote_timestamps = Hash.new { |h, k| h[k] = [] } 
  end

  def analyze
    read_votes
    detect_fraud
    generate_ranking
  end

  private

  def normalize_name(name)
    return '' if name.nil?
    normalized = name.downcase.gsub(/[^a-zа-я]/, '')
    normalized[0..7]
  end

  def read_votes
    File.foreach(@file_path) do |line|
      next unless line.include?('candidate:')
      
      ip = line[/ip: ([^,]+)/, 1]
      original_name = line[/candidate: ([^\n]+)/, 1].strip
      timestamp_str = line[/time: ([^\n]+)/, 1]
      
      next unless timestamp_str 
      
      begin
        timestamp = Time.parse(timestamp_str)
      rescue ArgumentError
        next 
      end
      
      normalized_key = normalize_name(original_name)
      @original_names[normalized_key] ||= original_name
      
      @candidate_names.add(normalized_key)
      @candidate_votes[normalized_key] += 1
      @ip_votes[ip] << normalized_key
      @candidate_ips[normalized_key].add(ip)
      @vote_timestamps[normalized_key] << timestamp
    end
  end

  def check_time_based_fraud(candidate, timestamps)
    return 0 if timestamps.size < 10 
    
    timestamps.sort!
    max_votes_in_60s = 0
    
    left = 0
    (0...timestamps.size).each do |right|
      while timestamps[right] - timestamps[left] > 60
        left += 1
      end
      
      votes_in_window = right - left + 1
      max_votes_in_60s = [max_votes_in_60s, votes_in_window].max
    end
    
    if max_votes_in_60s > 20
      max_votes_in_60s * 5 
    else
      0
    end
  end

  def detect_fraud
    suspicious_scores = Hash.new(0)
    
    @ip_votes.each do |ip, votes|
      if votes.uniq.size == 1 && votes.size > 15
        candidate = votes.first
        suspicious_scores[candidate] += votes.size * 2
      end
    end
    
    @ip_votes.each do |ip, votes|
      if votes.size > 30
        votes.uniq.each do |candidate|
          suspicious_scores[candidate] += votes.size / votes.uniq.size
        end
      end
    end
    
    @candidate_ips.each do |candidate, ips|
      if @candidate_votes[candidate] > 50 && ips.size < 5
        suspicious_scores[candidate] += (@candidate_votes[candidate] / ips.size) * 3
      end
    end
    
    @vote_timestamps.each do |candidate, timestamps|
      time_score = check_time_based_fraud(candidate, timestamps)
      suspicious_scores[candidate] += time_score
    end
    
    @candidate_votes.each do |candidate, votes|
      if votes > 1000 && suspicious_scores[candidate] == 0
        suspicious_scores[candidate] += votes / 10
      end
    end
    
    sorted_suspicious = suspicious_scores.sort_by { |_, score| -score }
    
    fraud_candidates_normalized = []
    used_names = Set.new
    
    sorted_suspicious.each do |candidate, score|
      original_name = @original_names[candidate] || candidate
      normalized_base = normalize_name(original_name)
      
      next if used_names.include?(normalized_base)
      
      if score > 0 && fraud_candidates_normalized.size < 2
        fraud_candidates_normalized << candidate
        used_names.add(normalized_base)
      end
      break if fraud_candidates_normalized.size == 2
    end
    
    if fraud_candidates_normalized.size < 2
      top_candidates = @candidate_votes.sort_by { |_, votes| -votes }
      top_candidates.each do |candidate, votes|
        original_name = @original_names[candidate] || candidate
        normalized_base = normalize_name(original_name)
        
        next if used_names.include?(normalized_base)
        
        if !fraud_candidates_normalized.include?(candidate) && fraud_candidates_normalized.size < 2
          fraud_candidates_normalized << candidate
          used_names.add(normalized_base)
        end
        break if fraud_candidates_normalized.size == 2
      end
    end
    
    @fraud_candidates = fraud_candidates_normalized.map do |normalized_name|
      @original_names[normalized_name] || normalized_name
    end
  end

  def generate_ranking
    fraud_normalized = @fraud_candidates.map { |name| normalize_name(name) }
    clean_votes = @candidate_votes.reject { |candidate, _| fraud_normalized.include?(candidate) }
    
    ranking = clean_votes.sort_by { |_, votes| -votes }
    
    puts "Подозрительные кандидаты (накрутка): #{@fraud_candidates.join(', ')}"
    puts "\nИтоговый рейтинг (первые 20):"
    
    ranking.first(20).each_with_index do |(normalized_key, votes), index|
      original_name = @original_names[normalized_key] || normalized_key
      puts "#{index + 1}. #{original_name}: #{votes} голосов"
    end
    
    puts "\nСтатистика подозрительных кандидатов:"
    @fraud_candidates.each do |original_name|
      normalized_key = normalize_name(original_name)
      votes = @candidate_votes[normalized_key]
      ips = @candidate_ips[normalized_key].size
      avg_votes = ips > 0 ? votes.to_f / ips : 0
      
      timestamps = @vote_timestamps[normalized_key]
      time_analysis = ""
      if timestamps && timestamps.size > 1
        timestamps.sort!
        time_range = timestamps.last - timestamps.first
        votes_per_second = timestamps.size / time_range.to_f
        time_analysis = ", #{votes_per_second.round(2)} голосов/сек"
      end
      
      puts "#{original_name}: #{votes} голосов с #{ips} уникальных IP (в среднем #{avg_votes.round(2)} голосов/IP#{time_analysis})"
    end
  end
end

analyzer = VoteAnalyzer.new('votes_12.txt')
analyzer.analyze