module RequestLogAnalyzer::Tracker
  class Uniques < Base
   # Check if duration and catagory option have been received,
    def prepare
      options[:field] ||= :remote_ip
      @ips = Hash.new
    end

    # Returns the title of this tracker for reports
    def title
      options[:title]  || 'Unique visitors by IP'
    end

    # Check if the timestamp in the request and store it.
    # <tt>request</tt> The request.
    def update(request)
      ip = request.first(options[:field])
      if (@ips.key?(ip))
        @ips[ip] += 1
      else
        @ips[ip] = 1
      end
    end

    def report(output)
      output.title(title)
      output << "Number of unique IPs visited: #{ @ips.length }. \n"

      output << "Most persistent visitors: \n"
      sortedips = @ips.sort_by { |ip, count| count }

      sortedips = sortedips.last(20)
      sortedips = sortedips.reverse

      output.table({}, { align: :right }, { type: :ratio, width: :rest, treshold: 0.15 }) do |rows|
        sortedips.each_with_index do |item, index|
          rows << [item[0], item[1]]
        end
      end

      output << "Number of pages viewed per unique IP: \n"
      sortedips = @ips.sort_by { |ip, count| count }
      sortedips = sortedips.group_by { |ip, count| count }
      sortedips = sortedips.sort_by { |group, freq| group }

      output.table({}, { align: :right }, { type: :ratio, width: :rest, treshold: 0.15 }) do |rows|
        sortedips.each_with_index do |item, index|
          ratio = item[1].length.to_f * 100 / @ips.length.to_f
          rows << [ item[0], item[1].length, "#{ ratio.round(1) }%" ]
        end
      end

    end

    # Returns hash for YAML exporting
    def to_yaml_object
      # not implemented because I don't use it
      yaml_object = {}
      yaml_object
    end
  end
end
