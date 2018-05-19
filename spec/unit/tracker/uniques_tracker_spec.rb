require 'spec_helper'

describe RequestLogAnalyzer::Tracker::Uniques do

  describe '#report' do
    before(:each) do
      @tracker = RequestLogAnalyzer::Tracker::Uniques.new()
      @tracker.prepare
    end
  end
  
end
