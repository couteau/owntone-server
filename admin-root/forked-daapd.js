/**
 * @author Stuart C. Naifeh
 * @copyright 2014 Stuart C. Naifeh <stu@naifeh.org>
 * @license GPL 2.0
 * 
 * Copyright (C) 2014 Stuart C. Naifeh
 * Released under the GPL 2.0 license
 * http://www.gnu.org/licenses/gpl-2.0.html
 */
var orig_config;
var uptime = 0;
var utInterval = 0;

$(function() {
  var tooltips = $("[title]").tooltip({
    position : {
      my : "left top",
      at : "right+5 top-5"
    }
  });

  $("#config_form").tabs();

  $("#speed").selectmenu();

  $("#initrescan").click(function() {
    $.ajax("/admin/initrescan");
  });
  $("#fullrescan").click(function() {
    $.ajax("/admin/fullrescan");
  });

  $('.number_input').on('input', function() {
    var input = $(this);
    var re = /^[\d]+$/;
    var is_valid = re.test(input.val()) && (parseInt(input.val()) != 0);
    if (is_valid) {
      input.removeClass("invalid");
    } else {
      input.addClass("invalid");
    }
  });

  updateStatus();
  updateConfig();

  $(".add_directory").click(function(e) {
    e.preventDefault();
    addDirectory($(this).parent("div")[0], "");
  });

  $(".directory_list").on("click", ".remove_directory", function(e) {
    e.preventDefault();
    $(this).parent('div').remove();
  });

  $(".save").click(function(e) {
    e.preventDefault();
    var invalid = $(".invalid");
    if (invalid.length > 0)
      return;

    $(".save").prop("disabled", true);

    var new_config = {
      logfile : $("#logfile").val(),
      loglevel : $("#loglevel option:selected").index(),
      ipv6 : $("#ipv6").is(":checked") ? 1 : 0,
      port : $("#port").val(),
      daapcache_threshold : $("#daapcache_threshold").val(),
      directories : $('input[name="directories[]"]').map(function() {
        return $(this).val();
      }).get(),
      podcasts : $('input[name="podcast_directories[]"]').map(function() {
        return $(this).val();
      }).get(),
      audiobooks : $('input[name="audiobook_directories[]"]').map(function() {
        return $(this).val();
      }).get(),
      compilations : $('input[name="compilation_directories[]"]').map(function() {
        return $(this).val();
      }).get(),
      compilation_artist : $("#compilation_artist").val()
    };

    $.each(orig_config, function(k, v) {
      if (new_config[k] == v) {
        delete new_config[k];
      } else if ($.isArray(v) && $.isArray(new_config[k])) {
        if (v.length == new_config[k].length) {
          var i;
          for ( i = 0; i < v.length && v[i] == new_config[k][i]; i++);
          if (i == v.length)//arrays are equal
            delete new_config[k];
          else
            new_config[k] = new_config[k].join(':');
        }
        else
          new_config[k] = new_config[k].join(':');
      }
    });

    if (!$.isEmptyObject(new_config)) {
      $.post("/admin/setconfig", new_config).always( function() {
        $(".save").prop("disabled", false);
      });
    } else {
      $(".save").prop("disabled", false);
    }
  });

  $(".reset").click(function(e) {
    e.preventDefault();
    updateConfig();
  });
});

function addDirectory(wrapper, s) {
  var n = wrapper.id;
  $(wrapper).append('<div class="fd_option extra_dir"><input type="text" name="' + n + '[]" value="' + s + '"/><a href="#" class="remove_directory">Remove</a></div>');
}

function updateConfig() {
  $.getJSON("/admin/getconfig", function(conf) {
    orig_config = conf;
    $(".extra_dir").remove();

    $("#logfile").val(conf.logfile);
    $("#loglevel").prop("selectedIndex", conf.loglevel);
    $("#ipv6").prop("checked", Boolean(conf.ipv6));
    $("#port").val(conf.port);
    $("#daapcache_threshold").val(conf.daapcache_threshold);

    if (conf.directories.length) {
      var wrapper = $("#directories")[0];
      $("#library").val(conf.directories[0]);
      var i;
      for ( i = 1; i < conf.directories.length; i++) {
        addDirectory(wrapper, conf.directories[i]);
      }
    }

    if (conf.podcasts.length) {
      var wrapper = $("#podcast_directories")[0];
      $("#podcasts").val(conf.podcasts[0]);
      for ( i = 1; i < conf.podcasts.length; i++) {
        addDirectory(wrapper, conf.podcasts[i]);
      }
    }

    if (conf.audiobooks.length) {
      var wrapper = $("#audiobooks_directories")[0];
      $("#audiobooks").val(conf.audiobooks[0]);
      for ( i = 1; i < conf.audiobooks.length; i++) {
        addDirectory(wrapper, conf.audiobooks[i]);
      }
    }

    if (conf.compilations.length) {
      var wrapper = $("#compilation_directories")[0];
      $("#compilations").val(conf.compilations[0]);
      for ( i = 1; i < conf.compilations.length; i++) {
        addDirectory(wrapper, conf.compilations[i]);
      }
    }

    $("#compilation_artist").val(conf.compilation_artist);
  });
}

function updateStatus() {
  $.getJSON("/admin/getstatus", doUpdate).always(setStatusTimer);
}

function updateUptime(u) {
  var s,
      m,
      h,
      d;
  s = u % 60;
  u -= s;
  m = u % 3600;
  u -= m;
  m /= 60;
  h = u % 86400;
  u -= h;
  h /= 3600;
  d = u / 86400;
  $("#uptime").html(d + " days, " + h + " hours, " + m + " minutes, " + s + " seconds");
}

function doUpdate(st) {
  $("#libname").html(st.name);
  $("#version").html(st.version);
  $("#db_version").html(st.db_version);
  uptime = st.uptime;
  updateUptime(st.uptime);
  $("#song_count").html(st.total_songs);
  $("#pl_count").html(st.total_playlists);
  var pl_status = ["", "", "stopped", "paused", "playing"];
  $("#player_status").html(pl_status[st.play_status]);
}

function incTime() {
  updateUptime(++uptime);
}

function setStatusTimer() {
  clearInterval(utInterval);
  utInterval = setInterval(incTime, 1000);
  setTimeout(updateStatus, 5000);
}
