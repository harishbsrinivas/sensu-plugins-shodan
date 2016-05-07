#! /usr/bin/env ruby
#
#   check-shodan
#
# DESCRIPTION:
#   Query Shodan.io for the specified terms and present a list of hosts matched.
#
#
# OUTPUT:
#   plain text
#
# PLATFORMS:
#   Linux, BSD, Windows
#
# DEPENDENCIES:
#   gem: 'faraday'
#   gem: 'faraday_middleware'
#   gem: 'json'
#   gem: 'trollop'
#   gem: 'yaml'
#   gem: sensu-plugin
#
# USAGE:
#
# NOTES:
#
# LICENSE:
#   Copyright 2016 Swiggy.in  <Sensu-Plugins>
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

require 'faraday'
require 'faraday_middleware'
require 'json'
require 'yaml'
require 'sensu-plugin/check/cli'


class CheckShodan < Sensu::Plugin::Check::CLI
  option :apikey,
         short: '-a TYPE[,TYPE]',
         description: 'API Key to access Shodan.io',
         proc: proc { |a| a.split(',') }

  option :query,
         short: '-q TYPE[,TYPE]',
         description: 'Query term',
         proc: proc { |a| a.split(',') }

  option :dryrun,
         short: '-d TYPE[,TYPE]',
         description: 'dryrun',
         proc: proc { |a| a.split(',') }

  option :whitelist,
         short: '-l TYPE[,TYPE]',
         description: 'YAML file contining host to be excluded',
         proc: proc { |a| a.split(',') }

  option :bwarn,
         short: '-w count',
         description: 'Warn if COUNT or more hosts are found',
         proc: proc(&:to_i),
         default: 1

  option :bcrit,
         short: '-c count',
         description: 'Critical if COUNT or more hosts are found',
         proc: proc(&:to_i),
         default: 3

  def initialize
    super
    @crit = []
    @warn = []
  end

  def check_shodan


    if config[:whitelist].nil?
      @whitelist = Array.new
    else
      @whitelist = YAML.load(File.open(config[:whitelist].first, 'r'))
    end


    @ips = Array.new
    if config[:apikey] && config[:query]
      conn = Faraday.new(:url => 'https://api.shodan.io')
      response = conn.get "/shodan/host/search?key=#{config[:apikey].first}&query=#{config[:query].first}"
      if response.status == 200
        parsed_output = JSON.parse(response.body)
        parsed_output['matches'].each do |host|
          if !@whitelist.include?(host['ip_str'])
            @ips << host['ip_str']
          end
        end


        @ips.each do |ip|
          response = conn.get "/shodan/host/#{ip}?key=#{config[:apikey].first}"
          parsed_output = JSON.parse(response.body)
          if @ips.count >= config[:bwarn]
            @warn << "IP:#{ip} => Ports:#{parsed_output['ports']}"
          end

          if @ips.count >= config[:bcrit]
            @crit << "IP:#{ip} => Ports:#{parsed_output['ports']}"
          end
        end
      end
    end
  end


  def usage_summary
    puts "found #{@ips.count} IP(s) in Shodan.io!"
    if @crit.count >= @warn.count
      return @crit.join(',')
    elsif @crit.count < @warn.count
      return @warn.join(',')
    end
  end


  def run
    check_shodan()
    critical usage_summary unless @crit.empty?
    warning usage_summary unless @warn.empty?
    ok "No IPs found on Shodan.io!"
  end
end
