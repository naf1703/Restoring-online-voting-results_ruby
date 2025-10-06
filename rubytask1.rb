require 'set'
require 'time'

class VoteAnalyzer
  def initialize(file_path)
    @file_path = file_path
    @votes = []
    @name_groups = {}
    @corrected_votes = Hash.new(0)
  end

  def analyze
    read_votes
    find_correct_names
    detect_fraud
    generate_ranking
  end

  private

  def read_votes
    File.foreach(@file_path) do |line|
      next unless line.include?('candidate:')
      
      ip = line[/ip: ([^,]+)/, 1]
      candidate_name = line[/candidate: ([^\n]+)/, 1]&.strip
      timestamp_str = line[/time: ([^\n]+)/, 1]
      
      next unless candidate_name && timestamp_str
      
      begin
        timestamp = Time.parse(timestamp_str)
        @votes << {ip: ip, candidate: candidate_name, time: timestamp}
      rescue ArgumentError
        next
      end
    end
  end

  def find_correct_names
    name_counts = Hash.new(0)
    @votes.each { |vote| name_counts[vote[:candidate]] += 1 }
    
    names = name_counts.keys.sort_by { |name| -name_counts[name] }
    
    names.each do |name|
      found_group = false
      
      @name_groups.each do |correct_name, variants|
        if name_similar?(name, correct_name)
          variants << name
          found_group = true
          break
        end
      end
      
      unless found_group
        @name_groups[name] = Set.new([name])
      end
    end
    
    @name_groups.each do |correct_name, variants|
      variants.each do |variant|
        @corrected_votes[correct_name] += name_counts[variant]
      end
    end
  end

  def name_similar?(name1, name2)
    return true if name1 == name2
    
    n1 = name1.downcase.gsub(/[^a-z]/, '')
    n2 = name2.downcase.gsub(/[^a-z]/, '')
    
    return false if (n1.length - n2.length).abs > 2
    
    distance = levenshtein_distance(n1, n2)
    distance <= 2
  end

  def levenshtein_distance(str1, str2)
    n = str1.length
    m = str2.length
    return m if n == 0
    return n if m == 0

    d = Array.new(n + 1) { Array.new(m + 1) }

    (0..n).each { |i| d[i][0] = i }
    (0..m).each { |j| d[0][j] = j }

    (1..n).each do |i|
      (1..m).each do |j|
        cost = str1[i - 1] == str2[j - 1] ? 0 : 1
        d[i][j] = [
          d[i - 1][j] + 1,
          d[i][j - 1] + 1,
          d[i - 1][j - 1] + cost
        ].min
      end
    end

    d[n][m]
  end

  def detect_fraud
    candidate_stats = {}
    
    @name_groups.each_key do |candidate|
      candidate_votes = @votes.select { |v| @name_groups[candidate].include?(v[:candidate]) }
      
      # Анализируем IP
      ips = candidate_votes.map { |v| v[:ip] }.uniq
      ip_votes_count = Hash.new(0)
      candidate_votes.each { |v| ip_votes_count[v[:ip]] += 1 }
      
      # Анализируем время
      timestamps = candidate_votes.map { |v| v[:time] }.sort
      time_range = timestamps.size > 1 ? timestamps.last - timestamps.first : 0
      
      # Анализируем распределение времени голосования
      time_clustering = calculate_time_clustering(timestamps)
      
      candidate_stats[candidate] = {
        total_votes: candidate_votes.size,
        unique_ips: ips.size,
        votes_per_ip: candidate_votes.size.to_f / ips.size,
        time_range: time_range,
        max_votes_from_single_ip: ip_votes_count.values.max || 0,
        time_clustering: time_clustering,
        ip_votes_count: ip_votes_count
      }
    end
    
    # Ищем мошенников
    suspicious = []
    
    candidate_stats.each do |candidate, stats|
      # Пропускаем Freddie Kertzmann
      next if candidate.include?('Freddie') && candidate.include?('Kertzmann')
      
      fraud_score = 0
      reasons = []
      
      # Критерий 1: Все голоса с одного IP
      if stats[:unique_ips] == 1 && stats[:total_votes] > 2
        fraud_score += 1000
        reasons << "all votes from single IP"
      end
      
      # Критерий 2: Очень высокая концентрация голосов с одного IP
      if stats[:max_votes_from_single_ip] > stats[:total_votes] * 0.8 && stats[:total_votes] > 10
        fraud_score += 800
        reasons << "high concentration from single IP (#{stats[:max_votes_from_single_ip]} from one IP)"
      elsif stats[:max_votes_from_single_ip] > 50
        fraud_score += 500
        reasons << "many votes from single IP (#{stats[:max_votes_from_single_ip]})"
      end
      
      # Критерий 3: Очень короткое время для большого количества голосов
      if stats[:total_votes] > 20 && stats[:time_range] < 120 # 2 минуты
        fraud_score += 600
        reasons << "many votes in very short time (#{stats[:time_range].round(1)}s)"
      elsif stats[:total_votes] > 10 && stats[:time_range] < 60 # 1 минута
        fraud_score += 400
        reasons << "votes in very short time (#{stats[:time_range].round(1)}s)"
      end
      
      # Критерий 4: Высокая кластеризация по времени
      if stats[:time_clustering] > 0.7 && stats[:total_votes] > 15
        fraud_score += 300
        reasons << "high time clustering (#{(stats[:time_clustering] * 100).round(1)}%)"
      end
      
      # Критерий 5: Подозрительное соотношение голосов к IP
      if stats[:votes_per_ip] > 30
        fraud_score += 200
        reasons << "high votes per IP ratio (#{stats[:votes_per_ip].round(1)})"
      end
      
      if fraud_score > 0
        suspicious << {
          candidate: candidate,
          score: fraud_score,
          reasons: reasons,
          votes: stats[:total_votes]
        }
      end
    end
    
    # Сортируем по уровню подозрительности и берем двух самых подозрительных
    suspicious.sort_by! { |s| -s[:score] }
    @fraud_candidates = suspicious.first(2).map { |s| s[:candidate] }
  end

  def calculate_time_clustering(timestamps)
    return 0 if timestamps.size < 2
    
    sorted_times = timestamps.sort
    total_range = sorted_times.last - sorted_times.first
    return 1 if total_range == 0
    
    # Считаем, какая доля голосов попадает в 5% временного окна
    window_5_percent = total_range * 0.05
    max_votes_in_window = 0
    
    sorted_times.each_with_index do |time, i|
      window_end = time + window_5_percent
      votes_in_window = sorted_times.count { |t| t >= time && t <= window_end }
      max_votes_in_window = [max_votes_in_window, votes_in_window].max
    end
    
    max_votes_in_window.to_f / timestamps.size
  end

  def generate_ranking
    # Убираем мошенников из рейтинга
    clean_ranking = @corrected_votes.reject { |candidate, _| @fraud_candidates.include?(candidate) }
    
    # Сортируем по количеству голосов
    sorted_ranking = clean_ranking.sort_by { |_, votes| -votes }
    
    puts "Fraud Candidates:"
    @fraud_candidates.each do |candidate|
      votes = @corrected_votes[candidate]
      puts "#{candidate}: #{votes}"
    end
    
    puts "\nVote counts:"
    # Выводим только топ-20 кандидатов
    sorted_ranking.first(20).each do |candidate, votes|
      puts "#{candidate}: #{votes}"
    end
  end
end

# Запуск анализа
analyzer = VoteAnalyzer.new('votes_12.txt')
analyzer.analyze