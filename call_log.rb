#!/usr/bin/ruby

require 'json'
require 'uri'
require 'net/http'
require 'openssl'

HOST = '192.168.1.254'.freeze

# http://stackoverflow.com/questions/4136248/how-to-generate-a-human-readable-time-range-using-ruby-on-rails
def humanize(secs)
  translations = [[60, :seconds], [60, :minutes], [24, :hours], [1000, :days]]
  translations.map do |count, name|
    if secs > 0
      secs, n = secs.divmod(count)
      "#{n.to_i} #{name}"
    end
  end.compact.reverse.join(' ')
end

def get_uri(path)
  URI.parse("https://#{HOST}" + path)
end

def env_file
  File.expand_path('~/.env/freebox')
end

def read_env_lines
  File.exist?(env_file) || raise("Create #{env_file}")
  File.readlines(env_file)
end

def env_lines
  @env_lines ||= read_env_lines
end

def load_env(name)
  found = env_lines.find { |l| l.start_with?(name) }
  return if found.nil?

  found.split('=').last.chomp
end

def post_json(uri)
  Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
end

def request_auth(http)
  req = post_json(
    get_uri('/api/v4/login/authorize/')
  )

  req.body = JSON(
    app_id: 'get_call_logs',
    app_name: 'Get call logs',
    app_version: '0.0.1',
    device_name: Socket.gethostname
  )
  res = http.request(req)
  j = JSON.parse(res.body)

  j.fetch('success') || raise('Request auth failed!')

  result = j.fetch('result')
  track_id = result.fetch('track_id')
  app_token = result.fetch('app_token')

  puts "Update env file: #{env_file}, with tokens below"
  puts "TRACK_ID=#{track_id}"
  puts "APP_TOKEN=#{app_token}"
  exit(1)
end

def auth_track(http, track)
  req = http.get(
    get_uri("/api/v4/login/authorize/#{track}")
  )

  res = JSON.parse(req.body)
  res.fetch('success') || raise('Could not auth track')

  result = res.fetch('result')
  status = result.fetch('status')
  challenge = result.fetch('challenge')
  _password_salt = result.fetch('password_salt')

  status != 'granted' && raise("Unauthorized track : status=#{status}")
  challenge
end

def gen_password(token, challenge)
  OpenSSL::HMAC.hexdigest('sha1', token, challenge)
end

def login(http, password)
  req = post_json(
    get_uri('/api/v4/login/session/')
  )

  req.body = JSON(
    app_id: 'get_call_logs',
    password: password,
  )

  res = http.request(req)
  j = JSON.parse(res.body)

  if !j.fetch('success')
    warn(j)
    raise('Loging failed!')
  end

  result = j.fetch('result')
  result.fetch('session_token')
end

def get_call_logs(http, session_token)
  req = Net::HTTP::Get.new(get_uri('/api/v4/call/log/'))
  req.add_field('X-Fbx-App-Auth', session_token)
  req.add_field('Content-Type', 'application/json; charset=utf-8')
  res = http.request(req)
  j = JSON.parse(res.body)

  j.fetch('success') || raise('Failed getting call log')

  j.fetch('result')
end

track_id = load_env('TRACK_ID')
app_token = load_env('APP_TOKEN')

http = Net::HTTP.new(HOST, 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE

[track_id, app_token].any?(&:nil?) && request_auth(http)

challenge = auth_track(http, track_id)

session_token = login(http, gen_password(app_token, challenge))

calls = get_call_logs(http, session_token)

max = if (arg = ARGV[0])
        Integer(arg)
      else
        15
      end

batch = calls.first(max)
longuest = ->(param) { batch.max_by { |c| c.fetch(param).length }.fetch(param).length }
longuest_number = longuest.call('number')
longuest_name = longuest.call('name')
longuest_type = longuest.call('type')

lines = batch.map do |r|
  sprintf(
    "  %.16s  |  %-#{longuest_name}s  |  %-#{longuest_number}s  |  %-#{longuest_type}s  |  %s\n",
    Time.at(r.fetch('datetime')),
    r.fetch('name'),
    r.fetch('number'),
    r.fetch('type'),
    humanize(r.fetch('duration')).rjust(22),
  )
end

printf(
  "  %-16s  |  %-#{longuest_name}s  |  %-#{longuest_number}s  |  %-#{longuest_type}s  |  %s\n",
  'TIMESTAMP',
  'NAME',
  'NUMBER',
  'TYPE',
  'DURATION',
)

longuest_line = lines.max_by(&:length)
puts '-' * (longuest_line.length - 1)

puts lines
